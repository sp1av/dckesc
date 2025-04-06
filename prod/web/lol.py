from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

# Путь к директории с JSON-выводами Trivy
JSON_FOLDER = "./tmp"

@app.route('/')
def index():
    # Получаем список всех JSON файлов в папке
    json_files = [f for f in os.listdir(JSON_FOLDER) if f.endswith('.json')]
    return render_template('index.html', json_files=json_files)

@app.route('/scan/<filename>')
def scan_result(filename):
    # Загружаем данные из JSON файла
    try:
        with open(os.path.join(JSON_FOLDER, filename), 'r') as file:
            data = json.load(file)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    # Извлекаем результаты уязвимостей
    vulnerabilities = data.get("Results", [])
    return render_template('image-scan.html', data=data, vulnerabilities=vulnerabilities)

if __name__ == '__main__':
    app.run(debug=True, port=4444)
