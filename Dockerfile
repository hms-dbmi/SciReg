FROM dbmi/pynxgu

COPY app /app
RUN pip install -r /app/requirements.txt

RUN mkdir /entry_scripts/
COPY gunicorn-nginx-entry.sh /entry_scripts/
RUN chmod u+x /entry_scripts/gunicorn-nginx-entry.sh

COPY scireg.conf /etc/nginx/sites-available/pynxgu.conf

WORKDIR /

ENTRYPOINT ["/entry_scripts/gunicorn-nginx-entry.sh"]