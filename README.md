# 🔥 Apollo – Neural Network for Malware Detection

**Apollo** is an artificial neural network designed to analyze and detect computer threats using **heuristic analysis**.

## 🚀 Key Features
- Detection of malware using **neural network analysis**
- Utilizes **heuristic analysis** instead of traditional signature-based detection
- Automatic **model training** on new files
- **GUI interface** for easy file scanning

## 📌 Technologies Used
- **Programming Language:** Python
- **Frameworks:** TensorFlow, Keras, Scikit-Learn
- **Tools for PE file analysis:** pefile, pandas, numpy
- **Graphical Interface:** Tkinter, ttkbootstrap

## ⚙️ Installation and Execution

### 🔧 1. Install Required Libraries
```bash
pip install -r requirements.txt
```

### ▶️ 2. Run the Program
```bash
python analyze.py
```

## 📊 How Apollo Works
1. Loads a PE file (.exe, .dll, etc.)
2. Extracts **key file characteristics** (number of sections, entropy, entry point, etc.)
3. Passes them to the **neural network**
4. The neural network **determines the probability** of the file being malicious
5. Results are displayed in the **GUI**

## 📚 Project Structure
```
📂 Apollo  
 ├── 📂 antivirus_dense_model    # Saved neural network model
 ├── 📜 scaler.pkl               # Neural network scaler
 ├── 📜 all_features.csv         # File dataset  
 ├── 📜 analyze.py               # Main script
 ├── 📜 requirements.txt         # Required libraries  
 ├── 📜 README.md                # Project description  
```

## 🖥 Usage Instructions
1. **Run the program:** Open `analyze.py` to launch the GUI.
2. **File Analysis:**
   - Click **"Analyze File"**.
   - Select a file to scan.
   - Get the result indicating whether the file is malicious.
3. **Train the Neural Network:**
   - Click **"Train Network"**.
   - Wait for training to complete.
   - Apollo will update its knowledge and improve accuracy.
4. **View Statistics:**
   - The GUI displays the number of **safe** and **malicious files** in the dataset.

## 📜 License
MIT License

📌 **Author:** [Maksym Pasko](https://github.com/Wiloll)

