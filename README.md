# CyberCrypt Enterprise Security Suite

## Lancement local

```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

Compte initial :
- admin
- admin123

Changez ce mot de passe avant tout usage réel.

## Docker

```bash
docker build -t cybercrypt-enterprise .
docker run -p 8501:8501 -v cybercrypt_data:/app/data cybercrypt-enterprise
```
