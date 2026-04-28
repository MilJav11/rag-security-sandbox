import os
import chromadb

def init_db():
    print("Initializing ChromaDB...")
    client = chromadb.PersistentClient(path="./chroma_data")
    
    collection = client.get_or_create_collection(name="rag_policies")
    
    print("Reading data/policy_poisoned.txt...")
    with open("data/policy_poisoned.txt", "r") as f:
        content = f.read()
    
    print("Adding document to collection...")
    collection.add(
        documents=[content],
        metadatas=[{"source": "policy_poisoned.txt"}],
        ids=["doc1"]
    )
    
    print("Database initialized successfully!")

if __name__ == "__main__":
    init_db()
