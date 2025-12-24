import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import numpy as np
import tensorflow as tf
import pickle
import re
import threading
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, LSTM, Dense, Embedding, Bidirectional, Concatenate, Attention, Conv1D, Dropout
from tensorflow.keras.preprocessing.sequence import pad_sequences


MODEL_PATH = 'sql_defense_v20.h5'
TOKEN_PATH = 'tokenizer_v20.pickle'
MAX_LEN = 250       
LATENT_DIM = 512    
VOCAB_SIZE = 0      

class SQLFirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Neural SQL Firewall (V20 - Surgeon)")
        self.root.geometry("850x750")
        self.root.configure(bg="#f4f6f9")

        # Styling
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TFrame", background="#f4f6f9")
        self.style.configure("TLabel", background="#f4f6f9", font=("Segoe UI", 10))
        self.style.configure("TButton", font=("Segoe UI", 11, "bold"), padding=10)
        self.style.configure("Header.TLabel", font=("Segoe UI", 20, "bold"), foreground="#2c3e50")
        self.style.configure("Card.TFrame", background="white", relief="solid", borderwidth=1)

        self.create_widgets()
        
        # Async Load
        self.status_var = tk.StringVar(value="Initializing V20 Neural Engine...")
        self.lbl_status.config(textvariable=self.status_var, fg="orange")
        threading.Thread(target=self.load_ai_assets, daemon=True).start()

    def create_widgets(self):
        # --- HEADER ---
        header_frame = ttk.Frame(self.root)
        header_frame.pack(pady=20, padx=20, fill="x")
        ttk.Label(header_frame, text="SQL Injection Defense System", style="Header.TLabel").pack()
        self.lbl_status = tk.Label(header_frame, text="Waiting...", bg="#f4f6f9", font=("Segoe UI", 10))
        self.lbl_status.pack()

        # --- INPUT CARD ---
        in_frame = tk.Frame(self.root, bg="white", bd=1, relief="solid")
        in_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        tk.Label(in_frame, text=" INCOMING QUERY ", bg="#ecf0f1", fg="#333", font=("Segoe UI", 10, "bold"), anchor="w", padx=10, pady=5).pack(fill="x")
        
        self.txt_input = scrolledtext.ScrolledText(in_frame, height=6, font=("Consolas", 11), bd=0, padx=10, pady=10)
        self.txt_input.pack(fill="both", expand=True)
        self.txt_input.insert("1.0", "SELECT * FROM users WHERE id = ' + req.id")

        # --- CONTROLS ---
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        self.btn_scan = tk.Button(btn_frame, text="🛡️ SCAN & REPAIR", command=self.run_scan, 
                                  bg="#27ae60", fg="white", font=("Segoe UI", 11, "bold"), 
                                  relief="flat", padx=20, pady=5, state="disabled")
        self.btn_scan.pack(side="left", padx=10)
        
        tk.Button(btn_frame, text="CLEAR", command=self.clear, 
                  bg="#95a5a6", fg="white", font=("Segoe UI", 11, "bold"), 
                  relief="flat", padx=20, pady=5).pack(side="left")

        # --- OUTPUT CARD ---
        out_frame = tk.Frame(self.root, bg="white", bd=1, relief="solid")
        out_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        tk.Label(out_frame, text=" FIREWALL DECISION ", bg="#ecf0f1", fg="#333", font=("Segoe UI", 10, "bold"), anchor="w", padx=10, pady=5).pack(fill="x")
        
        # Status Badge
        self.lbl_verdict = tk.Label(out_frame, text="READY", font=("Segoe UI", 12, "bold"), bg="white", fg="#aaa", pady=10)
        self.lbl_verdict.pack()
        
        self.txt_output = scrolledtext.ScrolledText(out_frame, height=6, font=("Consolas", 11), bd=0, padx=10, pady=10, state="disabled", bg="#fcfcfc")
        self.txt_output.pack(fill="both", expand=True)

    # ==========================================
    # 2. AI LOADING (V20 ARCHITECTURE)
    # ==========================================
    def load_ai_assets(self):
        try:
            # 1. Load Tokenizer
            with open(TOKEN_PATH, 'rb') as handle:
                self.tokenizer = pickle.load(handle)
            global VOCAB_SIZE
            VOCAB_SIZE = len(self.tokenizer.word_index) + 1

            # 2. Rebuild V20 Architecture (CNN + BiLSTM + Attention)
            enc_in = Input(shape=(MAX_LEN,))
            enc_emb = Embedding(VOCAB_SIZE, 64)(enc_in)
            
            # The V20 Signature: Conv1D -> BiLSTM
            enc_conv = Conv1D(filters=256, kernel_size=4, padding='same', activation='relu')(enc_emb)
            enc_conv = Dropout(0.2)(enc_conv)
            
            enc_lstm = Bidirectional(LSTM(LATENT_DIM, return_sequences=True, return_state=True))
            enc_out, f_h, f_c, b_h, b_c = enc_lstm(enc_conv)
            state_h = Concatenate()([f_h, b_h])
            state_c = Concatenate()([f_c, b_c])
            enc_states = [state_h, state_c]

            dec_in = Input(shape=(MAX_LEN,))
            dec_emb_layer = Embedding(VOCAB_SIZE, 64)
            dec_emb = dec_emb_layer(dec_in)
            dec_lstm = LSTM(LATENT_DIM * 2, return_sequences=True, return_state=True)
            dec_out, _, _ = dec_lstm(dec_emb, initial_state=enc_states)

            attn_layer = Attention()
            attn_out = attn_layer([dec_out, enc_out])
            dec_concat = Concatenate(axis=-1)([dec_out, attn_out])
            
            dec_dense = Dense(VOCAB_SIZE, activation='softmax')
            final_out = dec_dense(dec_concat)

            # 3. Load Weights
            full_model = Model([enc_in, dec_in], final_out)
            full_model.load_weights(MODEL_PATH)

            # 4. Construct Inference Models
            self.encoder_model = Model(enc_in, [enc_out, state_h, state_c])

            dec_state_h = Input(shape=(LATENT_DIM * 2,))
            dec_state_c = Input(shape=(LATENT_DIM * 2,))
            dec_states_inputs = [dec_state_h, dec_state_c]
            enc_out_in = Input(shape=(MAX_LEN, LATENT_DIM * 2)) 

            dec_emb2 = dec_emb_layer(dec_in)
            dec_out2, state_h2, state_c2 = dec_lstm(dec_emb2, initial_state=dec_states_inputs)
            attn_out2 = attn_layer([dec_out2, enc_out_in])
            dec_concat2 = Concatenate(axis=-1)([dec_out2, attn_out2])
            final_out2 = dec_dense(dec_concat2)

            self.decoder_model = Model(
                [dec_in, enc_out_in] + dec_states_inputs,
                [final_out2, state_h2, state_c2]
            )

            # UI Success
            self.root.after(0, lambda: self.status_var.set("✅ V20 Model Loaded"))
            self.root.after(0, lambda: self.lbl_status.config(fg="green"))
            self.root.after(0, lambda: self.btn_scan.config(state="normal"))

        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"Load Error: {e}"))
            self.root.after(0, lambda: self.lbl_status.config(fg="red"))

    # ==========================================
    # 3. LOGIC (SMART CLEAN & PREDICT)
    # ==========================================
    def smart_clean(self, text):
        """V20 Hybrid Cleaning Logic"""
        text = str(text)
        text = re.sub(r'[*\/]{2,}', ' ', text)
        return re.sub(r'\s+', ' ', text).strip().lower()

    def fix_query(self, raw):
        tok = self.smart_clean(raw)
        seq = self.tokenizer.texts_to_sequences([tok])
        enc_in = pad_sequences(seq, maxlen=MAX_LEN, padding='post')
        
        # Encode
        enc_outs, h, c = self.encoder_model.predict(enc_in, verbose=0)
        
        # Decode
        target = np.zeros((1, 1)); target[0, 0] = self.tokenizer.word_index['\t']
        stop = False; decoded = ""
        
        while not stop:
            out, h, c = self.decoder_model.predict([target, enc_outs, h, c], verbose=0)
            idx = np.argmax(out[0, -1, :])
            char = self.tokenizer.index_word.get(idx, '')
            
            if char == '\n' or len(decoded) > MAX_LEN: stop = True
            else: decoded += char
            target[0, 0] = idx
            
        return decoded

    def run_scan(self):
        raw = self.txt_input.get("1.0", tk.END).strip()
        if not raw: return
        
        self.btn_scan.config(text="Processing...", state="disabled", bg="#f39c12")
        self.root.update()
        
        try:
            fixed = self.fix_query(raw)
            
            # Post-Process Cleanup (Space fixing)
            fixed_clean = re.sub(r"'\s*\?", "?", fixed) # Fix ' ? -> ?
            fixed_clean = fixed_clean.replace(" ? ", " ? ")
            
            # Comparison Logic
            clean_in = self.smart_clean(raw)
            clean_out = self.smart_clean(fixed) # Compare apples to apples
            
            self.txt_output.config(state="normal")
            self.txt_output.delete("1.0", tk.END)
            
            # Guardrail: Check Verb Swap (Select -> Delete)
            verb_in = clean_in.split()[0] if clean_in else ""
            verb_out = clean_out.split()[0] if clean_out else ""
            
            if verb_in != verb_out:
                self.lbl_verdict.config(text="🚨 BLOCKED: LOGIC CHANGE", fg="#c0392b")
                self.txt_output.insert("1.0", f"Model attempted unsafe verb change ({verb_in} -> {verb_out}). Request blocked.")
            elif clean_in == clean_out:
                self.lbl_verdict.config(text="✅ QUERY SAFE", fg="#27ae60")
                self.txt_output.insert("1.0", "Query is valid. No injections detected.")
            else:
                self.lbl_verdict.config(text="⚠️ THREAT NEUTRALIZED", fg="#e67e22")
                self.txt_output.insert("1.0", fixed_clean)
                
            self.txt_output.config(state="disabled")
            
        except Exception as e:
            messagebox.showerror("Runtime Error", str(e))
        finally:
            self.btn_scan.config(text="🛡️ SCAN & REPAIR", state="normal", bg="#27ae60")

    def clear(self):
        self.txt_input.delete("1.0", tk.END)
        self.txt_output.config(state="normal")
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.config(state="disabled")
        self.lbl_verdict.config(text="READY", fg="#aaa")

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLFirewallApp(root)
    root.mainloop()