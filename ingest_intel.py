# ingest_intel.py
import os
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

# 1. Load your SOC runbooks or Threat Intel files (e.g., from a 'runbooks' folder)
loader = DirectoryLoader('./runbooks', glob="**/*.md", loader_cls=TextLoader)
documents = loader.load()

# 2. Split the documents into manageable chunks
text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
chunks = text_splitter.split_documents(documents)

# 3. Initialize a local, free embedding model
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

# 4. Store the embeddings in a local Chroma vector database
vectorstore = Chroma.from_documents(
    documents=chunks,
    embedding=embeddings,
    persist_directory="./chroma_db"
)

print(f"Successfully ingested {len(chunks)} intel chunks into the vector store.")
