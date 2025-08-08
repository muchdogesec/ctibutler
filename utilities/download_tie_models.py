from pathlib import Path
import requests

models_root = Path('tie_models')

def download_model(matrix: str, path: str):
    matrix_dir = models_root/matrix
    matrix_dir.mkdir(exist_ok=True, parents=True)
    model_path = matrix_dir/ path.split('/')[-1]
    with requests.get(path, stream=True) as resp:
        resp.raise_for_status()
        with model_path.open('wb') as f:
            for chunk in resp.iter_content(8*1024):
                f.write(chunk)
    return

if __name__ == '__main__':
    download_model('enterprise', 'https://models.ctibutler.com/attack-enterprise-15_0.npz')