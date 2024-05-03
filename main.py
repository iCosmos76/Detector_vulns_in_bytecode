import tkinter as tk
from tkinter import messagebox
import pandas as pd
import numpy as np
import os
import tensorflow as tf
import time
import re

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

def split_text_into_chars(text, char_size):
    chars = []
    for i in range(0, len(text), char_size):
        chars.append(text[i:i + char_size])
    return " ".join(chars) 

loading_working_dir = './'
ckpt_filepath = os.path.join(loading_working_dir, 'ckpt')
modelT = tf.keras.models.load_model(filepath=ckpt_filepath)

def predict_sample():
    sample_1 = sample_entry.get()
    
    if not sample_1:
        messagebox.showerror("Ошибка", "Поле ввода не может быть пустым.")
        return

    if not re.match(r'^0x[0-9a-fA-F]+$', sample_1):
        messagebox.showerror("Ошибка", "Неверный формат данных. Пожалуйста, введите данные в формате '0x...' и содержащие только символы '0123456789abcdef'.")
        return

    start_pred = "6080"
    handled_start_pred = split_text_into_chars(start_pred, 2)
    handled_start_pred = np.expand_dims(start_pred, axis=0)
    start_pred = tf.data.Dataset.from_tensors(handled_start_pred)

    modelT_preds_probs = modelT.predict(start_pred)

    sample_1 = sample_1.replace("0x73", "0x60")
    sample_1 = sample_1[2:]
    handled_sample_1 = split_text_into_chars(sample_1, 2)
    handled_sample_1 = np.expand_dims(handled_sample_1, axis=0)
    test_example = tf.data.Dataset.from_tensors(handled_sample_1)

    start_time = time.time()
    modelT_preds_probs = modelT.predict(test_example)
    end_time = time.time()
    prediction_time = end_time - start_time

    class_names = ['Access control', 'Arithmetic O/U', 'Reentrancy', 'Unchecked calls']

    vulnerabilities_count = 0
    vulnerabilities_text = ""

    for class_name, probability in zip(class_names, modelT_preds_probs):
        if round(float(probability[0][0]), 4) > 0.5:  # Указать пороговое значение для обнаружения уязвимостей
            vulnerabilities_count += 1
            vulnerabilities_text += f"\n**{class_name}: {round(float(probability[0][0]), 4)}**"
        else:
            vulnerabilities_text += f"\n{class_name}: {round(float(probability[0][0]), 4)}"

    if vulnerabilities_count > 0:
        if vulnerabilities_count == 1:
            messagebox.showwarning("Обнаружены уязвимости", f"Обнаружена {vulnerabilities_count} уязвимость.")
        else:
            messagebox.showwarning("Обнаружены уязвимости", f"Обнаружено {vulnerabilities_count} уязвимости.")
    else:
        messagebox.showinfo("Уязвимости не обнаружены", "Уязвимости не были найдены.")
    result_label.config(text=f"Прогнозы по классам:{vulnerabilities_text}")
    time_label.config(text=f"Время предсказания: {round(prediction_time, 2)} секунд")

def clear_input():
    sample_entry.delete(0, tk.END)
    result_label.config(text="")
    time_label.config(text="")
    length_label.config(text="Длина байт-кода: 0")

def on_text_changed(event):
    text = sample_entry.get()  # Получаем текст из текстового поля
    length_label.config(text=f"Длина байт-кода: {len(text)}")

def select_all(event):
    sample_entry.select_range(0, 'end')
    return 'break'

def on_paste(event):
    clipboard_content = root.clipboard_get()
    sample_entry.delete(0, tk.END)

# Tkinter GUI
root = tk.Tk()
root.title("Предсказание класса")

# Set window size
root.geometry("400x300")
root.minsize(400, 300)

# Input
sample_label = tk.Label(root, text="Введите образец:", font=("Arial", 12))
sample_label.pack()
sample_entry = tk.Entry(root, width=50, font=("Arial", 12))
sample_entry.pack(pady=10)
sample_entry.bind("<KeyRelease>", on_text_changed)  # Привязываем функцию к событию изменения текста в поле
sample_entry.bind("<Control-a>", select_all)
sample_entry.bind('<Control-v>', on_paste)

# Button Frame
button_frame = tk.Frame(root)
button_frame.pack()

# Predict Button
predict_button = tk.Button(button_frame, text="Предсказать", command=predict_sample, font=("Arial", 12))
predict_button.pack(side=tk.LEFT, padx=5)

# Clear Button
clear_button = tk.Button(button_frame, text="Очистить", command=clear_input, font=("Arial", 12))
clear_button.pack(side=tk.LEFT, padx=5)

# Length
length_label = tk.Label(root, text="Длина байт-кода: 0", font=("Arial", 12))
length_label.pack(pady=10)

length_label.config(text="Длина байт-кода: 0")

# Result
result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack()

# Time
time_label = tk.Label(root, text="", font=("Arial", 12))
time_label.pack()

root.mainloop()
