FROM python:3-windowsservercore

WORKDIR /app/webapp

COPY . /app/

RUN pip install -r /app/requirements.txt

EXPOSE 5000

CMD python kskcheck.py