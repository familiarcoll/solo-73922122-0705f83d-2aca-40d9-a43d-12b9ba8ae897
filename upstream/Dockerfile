FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

COPY app /srv/app

EXPOSE 8000 8443
# 单进程：uvicorn(8000 控制面) + TLS 终结器(8444) + 延迟前门(8443 业务入口)
CMD ["python", "-m", "app.main"]
