import pandas as pd
import requests
from io import StringIO
from datetime import datetime

OUTPUT_CSV = "legit_ch_url.csv"
BASE_URL = "https://portal.switch.ch/open-data/top1000/"
START_YEAR = 2017
START_MONTH = 7  # July 2017
TODAY = datetime.today()

def generate_urls():
    urls = [f"{BASE_URL}latest.csv"]  # Always get latest first

    for year in range(START_YEAR, TODAY.year + 1):
        for month in range(1, 13):
            if year == START_YEAR and month < START_MONTH:
                continue
            if year == TODAY.year and month > TODAY.month:
                continue

            ym = f"{year}{month:02}"
            url = f"{BASE_URL}top1000_{ym}.csv"
            urls.append(url)

    return urls

def fetch_and_merge_csvs(urls, timeout=10):
    dataframes = []
    for i, url in enumerate(urls):
        try:
            print(f"[{i+1}/{len(urls)}] Fetching: {url}")
            response = requests.get(url, timeout=timeout)  # <= TIMEOUT added here
            response.raise_for_status()
            df = pd.read_csv(StringIO(response.text))
            dataframes.append(df)
        except requests.exceptions.Timeout:
            print(f"[TIMEOUT] Skipped: {url}")
        except requests.exceptions.RequestException as e:
            print(f"[WARN] Failed to fetch {url}: {e}")
    return dataframes


def main():
    urls = generate_urls()
    dfs = fetch_and_merge_csvs(urls)
    if not dfs:
        print("[ERROR] No dataframes fetched.")
        return

    merged_df = pd.concat(dfs, ignore_index=True)
    merged_df.drop_duplicates(subset=["domainname"], inplace=True)
    merged_df["status"] = "legitimate"  # Optional: For ML labeling
    merged_df.to_csv(OUTPUT_CSV, index=False)
    print(f"[SUCCESS] Merged {len(merged_df)} unique domains into {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
