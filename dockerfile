FROM python:3.9-slim

# Установка nmap и создание пользователя
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 app

WORKDIR /app
RUN chown app:app /app

# Установка зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование кода
COPY --chown=app:app . .

# Создание директорий для логов и зашифрованных результатов
RUN mkdir -p encrypted_results logs && chown -R app:app encrypted_results logs

USER app

EXPOSE 5000

# Монтируем директории для сохранения данных и логов
VOLUME ["/app/encrypted_results", "/app/logs"]

CMD ["python", "scan_automation.py"]
