import json
import pandas as pd

from app.ml.suricata_features import (
    extract_suricata_flow_features,
)


EVE_PATH = "/var/log/suricata/eve.json"
OUTPUT_PATH = "data/ml/suricata_flows.csv"


def build_dataset():
    rows = []
    skipped = 0

    print("Reading Suricata EVE flows...")

    with open(
        EVE_PATH,
        "r",
        encoding="utf-8",
    ) as file:

        for line in file:
            try:
                event = json.loads(line)

                if event.get("event_type") != "flow":
                    continue

                features = (
                    extract_suricata_flow_features(
                        event
                    )
                )

                rows.append(features)

            except Exception:
                skipped += 1

    if not rows:
        raise RuntimeError(
            "No valid Suricata flow events found."
        )

    df = pd.DataFrame(rows)

    print("\nRows extracted:", len(df))
    print("Rows skipped  :", skipped)

    before = len(df)

    df.drop_duplicates(
        inplace=True
    )

    df.reset_index(
        drop=True,
        inplace=True,
    )

    print(
        "Duplicates removed:",
        before - len(df),
    )

    print(
        "Final dataset shape:",
        df.shape,
    )

    print("\nFeature columns:")
    for column in df.columns:
        print("-", column)

    df.to_csv(
        OUTPUT_PATH,
        index=False,
    )

    print(
        f"\nDataset saved to: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    build_dataset()
