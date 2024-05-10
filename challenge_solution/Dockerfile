# Use the official SageMath image as the base
FROM sagemath/sagemath:latest

RUN /home/sage/sage/local/var/lib/sage/venv-python3.11.1/bin/pip install pwntools

# Copy all local files in the folder to workdir
COPY * /home/sage
WORKDIR /home/sage
RUN sudo chown 1000:1000 solve-prg.py
RUN sudo chown 1000:1000 server.py
RUN sudo chmod u+x server.py

CMD ["python3 solve-prg.py"]


