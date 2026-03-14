import json

def export_to_json(results):

    with open("scan_results.json", "w") as file:
        json.dump(results, file, indent=4)

    print("\nResults exported to scan_results.json")