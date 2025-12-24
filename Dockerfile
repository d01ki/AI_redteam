FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# システム依存を最小にするため、必要最低限のみインストール
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 依存関係をインストール
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

# アプリケーションコードを配置
COPY . /app

# デフォルトのターゲットIPを環境変数で設定可能
ENV TARGET_IP=192.0.2.10
ENV PORT=8080

EXPOSE 8080

CMD ["python", "app.py"]
