FROM python:3.7
ADD . /www
WORKDIR /www
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "main:app"]