import nltk
import os

def download_and_verify():
    """Download NLTK data and verify it exists in the expected location."""
    print("Downloading NLTK punkt data...")
    nltk.download("punkt", quiet=False)
    
    # Verify download
    try:
        punkt_dir = nltk.data.find("tokenizers/punkt").path
        print(f"Found punkt data directory: {punkt_dir}")
        
        # Print the directory structure to understand what's available
        print(f"Directory contents: {os.listdir(punkt_dir)}")
        
        if 'PY3' in os.listdir(punkt_dir):
            py3_dir = os.path.join(punkt_dir, 'PY3')
            print(f"PY3 directory contents: {os.listdir(py3_dir)}")
            
            if 'english.pickle' in os.listdir(py3_dir):
                print("English punkt tokenizer found!")
                return True
    except Exception as e:
        print(f"Error examining punkt data: {e}")
    
    return False

if __name__ == "__main__":
    download_and_verify() 