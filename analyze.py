import shutil
import ttkbootstrap as ttk
from tkinter import filedialog
import ctypes
from tensorflow.keras.models import load_model, Sequential
import joblib
import os
import numpy as np
import pefile
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.layers import Dense, Dropout

def learn(learn_result):
    learn_result.config(text="Мережа навчається...", font=("Helvetica", 12), bootstyle="warning")
    app.update()
    try:
        shutil.rmtree('antivirus_dense_model')
        os.remove('scaler.pkl')
    except:
        print("Модель вже видалена")

    def load_data(csv_file):
        data = pd.read_csv(csv_file)
        X = data.drop(columns=['Hazard', 'filename'])
        y = data['Hazard']
        X = X.values
        y = y.values
        return X, y

    X, y = load_data('all_features.csv')

    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = Sequential([
        Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dropout(0.3),
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer='adam',
                  loss='binary_crossentropy',
                  metrics=['accuracy'])

    model.fit(X_train, y_train, epochs=100, batch_size=32, validation_split=0.1)

    test_loss, test_accuracy = model.evaluate(X_test, y_test)
    print(f"Точність на тестових даних: {test_accuracy * 100:.2f}%")

    if test_accuracy < 0.5:
        learn(learn_result)
    else:
        learn_result.config(text=f"Мережа навчена з {test_accuracy * 100:.2f}% точністю на тестових даних", font=("Helvetica", 12), bootstyle="info")
        app.update()

    model.save('antivirus_dense_model')
    joblib.dump(scaler, 'scaler.pkl')

def extract_features_from_pe(file_path):
    pe = pefile.PE(file_path)
    num_sections = len(pe.sections)
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    sections_mean_entropy = np.mean([section.get_entropy() for section in pe.sections])
    return np.array([num_sections, entry_point, image_base, file_alignment, size_of_image, dll_characteristics, sections_mean_entropy])

def process_file(file_path, file_name, is_malicious):
    data = []
    if os.path.isfile('all_features.csv'):
        existing_data = pd.read_csv('all_features.csv')
        existing_filenames = existing_data['filename'].tolist()
    else:
        existing_filenames = []

    if os.path.isfile(file_path) and file_name not in existing_filenames:
        features = extract_features_from_pe(file_path)
        features_with_label = np.append(features, is_malicious)
        data.append(features_with_label)

    if data:
        df = pd.DataFrame(data)
        if not os.path.isfile('all_features.csv'):
            columns = ['NumberOfSections', 'EntryPoint', 'ImageBase', 'FileAlignment',
                       'SizeOfImage', 'DllCharacteristics', 'SectionsMeanEntropy', 'Hazard', 'filename']
            df.columns = columns
            df['filename'] = file_name
        else:
            df['filename'] = file_name
        df.to_csv('all_features.csv', index=False, mode='a', header=not os.path.isfile('all_features.csv'))

def analyze_files(file_paths, result_label):
    results = []
    for file_path in file_paths:
        file_name = os.path.basename(file_path)
        features_scaled = prepare_file_for_analysis(file_path)
        prediction = model.predict(features_scaled)
        if prediction[0] > 0.5:
            result = f"Файл {file_name} шкідливий."
            results.append(result)
            is_malicious = 1
            result_label.config(text="\n".join(results), bootstyle="danger")
        else:
            result = f"Файл {file_name} не шкідливий."
            results.append(result)
            is_malicious = 0
            result_label.config(text="\n".join(results), bootstyle="success")
        process_file(file_path, file_name, is_malicious)

def prepare_file_for_analysis(file_path):
    features = extract_features_from_pe(file_path)
    features_scaled = scaler.transform(features.reshape(1, -1))
    return features_scaled

def select_files(result_label):
    try:
        global model
        model = load_model('antivirus_dense_model')

        global scaler
        scaler = joblib.load('scaler.pkl')
    except:
        ctypes.windll.user32.MessageBoxW(0, "Model or scaler are not installed! Please train the neural network.", 16)

    file_paths = filedialog.askopenfilenames(title="Виберіть PE-файли для аналізу", filetypes=[("Portable Executable files", "*.exe *.dll *.sys *.scr *.drv *.efi *.acm *.ax *.mui *.tsp")])
    if file_paths:
        analyze_files(file_paths, result_label)

def update_file_counters(counter_label):
    if os.path.isfile('all_features.csv'):
        data = pd.read_csv('all_features.csv')
        normal_count = (data['Hazard'] == 0).sum()
        malicious_count = (data['Hazard'] == 1).sum()
        counter_label.config(
            text=f"Звичайні файли: {normal_count}\nШкідливі файли: {malicious_count}",
            font=("Helvetica", 12),
            bootstyle="info"
        )
    else:
        counter_label.config(
            text="База даних відсутня",
            font=("Helvetica", 12),
            bootstyle="info"
        )
    counter_label.after(5000, lambda: update_file_counters(counter_label))

app = ttk.Window(themename="darkly")
app.title("Apollo")
app.geometry("600x400")
app.iconbitmap('ICO.ico')

title_label = ttk.Label(app, text="Antivirus File Analyzer", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

analyze_button = ttk.Button(app, text="Аналізувати файли", command=lambda: select_files(result_label), bootstyle="primary")
analyze_button.pack(pady=10)

learn_button = ttk.Button(app, text="Навчити мережу", command=lambda: learn(learn_result), bootstyle="primary")
learn_button.pack(pady=10)

result_label = ttk.Label(app, text="Виберіть файли для аналізу", font=("Helvetica", 12))
result_label.pack(pady=10)

learn_result = ttk.Label(app, text="Мережа в стандартному стані", font=("Helvetica", 12), bootstyle="secondary")
learn_result.pack(pady=10)

counter_label = ttk.Label(app, text="", font=("Helvetica", 12), bootstyle="secondary")
counter_label.pack(pady=10)

update_file_counters(counter_label)

app.mainloop()