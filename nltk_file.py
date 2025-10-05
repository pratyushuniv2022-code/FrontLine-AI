import nltk
import os

# Where to store the downloaded data
nltk_data_dir = os.path.join(os.getcwd(), "nltk_data")

# Download only what you need
nltk.download("punkt", download_dir=nltk_data_dir)
nltk.download("stopwords", download_dir=nltk_data_dir)

print("✅ NLTK data saved in:", nltk_data_dir)