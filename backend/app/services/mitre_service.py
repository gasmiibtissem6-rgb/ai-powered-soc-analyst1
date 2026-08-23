from mitreattack.stix20 import MitreAttackData


class MitreService:

    def __init__(self):
        self.attack_data = MitreAttackData(
            "data/enterprise-attack.json"
        )

    def validate_technique(self, technique_id: str) -> dict:
        technique_id = technique_id.upper().strip()

        techniques = self.attack_data.get_techniques()

        for technique in techniques:
            external_references = technique.get(
                "external_references",
                []
            )

            for reference in external_references:
                if reference.get("external_id") == technique_id:
                    return {
                        "technique_id": technique_id,
                        "name": technique.get("name"),
                        "description": technique.get("description"),
                        "valid": True,
                    }

        return {
            "technique_id": technique_id,
            "name": None,
            "description": None,
            "valid": False,
        }