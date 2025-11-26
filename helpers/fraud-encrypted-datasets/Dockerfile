FROM jupyter/base-notebook:latest

# Switch to root to install packages
USER root
RUN apt-get update && \
    apt-get install -y curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Return to jovyan (non-root user)
USER $NB_UID

RUN pip install onnx onnxruntime tf2onnx pandas keras tensorflow scikit-learn tf2onnx onnx pathlib matplotlib azure.storage.blob
