import json
from datetime import datetime


def export_to_json(results, filename=None):
    """
    Exporte les résultats du scan en JSON.
    Si aucun nom de fichier n'est fourni, un nom horodaté est généré
    automatiquement pour ne jamais écraser un scan précédent.
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.json"

    try:
        with open(filename, "w") as file:
            json.dump(results, file, indent=4)
        print(f"\nResults exported to {filename}")
    except OSError as e:
        print(f"\n[Erreur] Impossible d'exporter les résultats : {e}")
