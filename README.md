# Neural-SQL-Guard-Character-Level-WAF-with-Attention-CNN
A Deep Learning-based Web Application Firewall (WAF) that uses a Hybrid Neural Network (CNN + BiLSTM + Attention) to detect and surgically repair SQL Injection attacks in real-time. It operates at the character level to handle unknown vocabulary and complex syntax.

# 🛡️ Neural SQL Guard (V20)

> **A Self-Healing SQL Firewall powered by Character-Level Deep Learning.**

Traditional WAFs rely on regex and static rules that are easily bypassed by obfuscation or zero-day attacks. **Neural SQL Guard** is different. It uses a **Seq2Seq Hybrid Architecture (CNN + BiLSTM + Attention)** to *read* raw SQL queries character-by-character, *understand* their intent, and *surgically repair* vulnerabilities without breaking valid logic.

![Architecture Diagram](https://img.shields.io/badge/Architecture-CNN%20%2B%20BiLSTM%20%2B%20Attention-blueviolet)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange)
![License](https://img.shields.io/badge/License-MIT-green)

## 🧠 Core Features

* **Character-Level Processing:** Can read and repair queries involving table names it has never seen before (e.g., `legacy_cobol_system`, `pokemon_cards`).
* **Surgical Repair:** Instead of blocking requests, it fixes them.
    * *Input:* `SELECT * FROM users WHERE id = ' + req.id`
    * *Output:* `SELECT * FROM users WHERE id = ?`
* **Context Awareness:** Distinguishes between code and data. It won't break math equations (`1+1=2`) or valid strings (`O'Reilly`) inside quotes.
* **Hybrid Architecture (V20/V21):**
    * **CNN (Conv1D):** Groups characters into "syllables" for spelling stability.
    * **BiLSTM:** Understands the full context of the query (start to end).
    * **Attention Mechanism:** "Copy-pastes" unknown words directly from input to output to prevent hallucinations.
* **Garbage Collection:** Automatically strips WAF-bypass noise (e.g., `////****`, `Waitfor Delay`).

## 🏗️ Model Architecture

The model treats SQL injection prevention as a **Language Translation** problem (translating "Vulnerable SQL" to "Safe SQL").

1.  **Input:** Raw SQL string (Character Tokenized).
2.  **Encoder:**
    * **Embedding Layer:** Maps characters to vectors.
    * **Conv1D (CNN):** Extracts local features (n-grams) to stabilize spelling.
    * **Bi-Directional LSTM:** Captures long-range dependencies and context.
3.  **Attention Layer:** Focuses on relevant parts of the input sequence during decoding.
4.  **Decoder:** LSTM that generates the sanitized query character-by-character.

## 🚀 Getting Started

### Prerequisites
* Python 3.10+
* TensorFlow 2.x
* Pandas, NumPy, Scikit-learn

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/MohamedAliWerda/Neural-SQL-Guard-Character-Level-WAF-with-Attention-CNN.git](https://github.com/MohamedAliWerda/Neural-SQL-Guard-Character-Level-WAF-with-Attention-CNN.git)
    cd Neural-SQL-Guard-Character-Level-WAF-with-Attention-CNN
    ```

2.  **Install dependencies:**
    ```bash
    pip install tensorflow pandas numpy
    ```

3.  **Run the Desktop GUI (Inference):**
    ```bash
    python main.py
    ```

### Training the Model (Optional)
If you want to retrain the brain from scratch:

```bash
python sql_defense_v20.py
