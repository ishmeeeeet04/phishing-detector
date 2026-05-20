# prepare_dataset.py
# Reads real emails from SpamAssassin folders
# and saves them as a clean CSV for training

import os
import pandas as pd

def load_emails_from_folder(folder_path, label):
    emails = []
    print(f"Reading from: {folder_path}")

    for filename in os.listdir(folder_path):
        filepath = os.path.join(folder_path, filename)

        # Skip hidden files and non-files
        if filename.startswith(".") or not os.path.isfile(filepath):
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

                # Email format is: HEADERS blank line BODY
                # We split on the first blank line to get the body
                if "\n\n" in content:
                    body = content.split("\n\n", 1)[1]
                else:
                    body = content

                # Only keep first 5000 characters to save memory
                emails.append({
                    "label": label,
                    "text":  body[:5000]
                })

        except Exception as e:
            print(f"  Skipping {filename}: {e}")
            continue

    print(f"  Loaded {len(emails)} emails labelled '{label}'")
    return emails


if __name__ == "__main__":
    # These paths point to the folders inside data/
    ham_path  = os.path.join("data", "easy_ham")
    spam_path = os.path.join("data", "spam")

    # Check folders exist before starting
    if not os.path.exists(ham_path):
        print(f"ERROR: Cannot find {ham_path}")
        print("Make sure easy_ham folder is inside data/")
        exit()

    if not os.path.exists(spam_path):
        print(f"ERROR: Cannot find {spam_path}")
        print("Make sure spam folder is inside data/")
        exit()

    print("Loading legitimate emails...")
    ham  = load_emails_from_folder(ham_path,  "legitimate")

    print("\nLoading phishing emails...")
    spam = load_emails_from_folder(spam_path, "phishing")

    # Combine and shuffle
    df = pd.DataFrame(ham + spam)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Save to CSV
    output_path = os.path.join("data", "emails_real.csv")
    df.to_csv(output_path, index=False)

    print(f"\nDone! Saved to {output_path}")
    print(f"Total emails  : {len(df)}")
    print(f"Legitimate    : {sum(df.label == 'legitimate')}")
    print(f"Phishing      : {sum(df.label == 'phishing')}")