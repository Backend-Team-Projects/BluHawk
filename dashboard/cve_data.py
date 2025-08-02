
# import os
# import requests
# import zipfile
# import json
# from datetime import datetime
# from django.utils.dateparse import parse_datetime
# from dashboard.models import CveNvd
# from django.db import transaction

# def download_and_process_cve_feeds(years: int = 1, download_dir: str = "cve_feeds"):
#     """
#     Downloads and processes NVD CVE feeds and inserts/updates them in the CveNvd database using bulk operations.
#     """
#     base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"
#     current_year = datetime.now().year

#     feeds = [f"nvdcve-1.1-{year}.json.zip" for year in range(current_year, current_year - years, -1)]
#     feeds += ["nvdcve-1.1-recent.json.zip", "nvdcve-1.1-modified.json.zip"]

#     os.makedirs(download_dir, exist_ok=True)

#     for feed in feeds:
#         file_path = os.path.join(download_dir, feed)
#         url = f"{base_url}/{feed}"

#         # Download if not present
#         if not os.path.exists(file_path):
#             print(f"Downloading {feed}...")
#             response = requests.get(url)
#             response.raise_for_status()
#             with open(file_path, "wb") as f:
#                 f.write(response.content)

#         print(f"Processing {feed}...")
#         with zipfile.ZipFile(file_path, 'r') as zip_ref:
#             json_filename = zip_ref.namelist()[0]
#             with zip_ref.open(json_filename) as json_file:
#                 data = json.load(json_file)
#                 cve_items = data.get('CVE_Items', [])

#                 batch = []
#                 for item in cve_items:
#                     try:
#                         cve_id = item['cve']['CVE_data_meta']['ID']
#                         cve_type = item['cve'].get('data_type', 'CVE')
#                         cve_name = cve_id
#                         published = parse_datetime(item.get('publishedDate'))
#                         modified = parse_datetime(item.get('lastModifiedDate'))

#                         batch.append(CveNvd(
#                             id=cve_id,
#                             type=cve_type,
#                             name=cve_name,
#                             created=published,
#                             modified=modified,
#                             json_data=item
#                         ))

#                     except Exception as e:
#                         print(f"Skipping CVE due to error: {e}")

#                 # Use bulk upsert (Django 4.1+)
#                 try:
#                     with transaction.atomic():
#                         CveNvd.objects.bulk_create(
#                             batch,
#                             batch_size=500,
#                             update_conflicts=True,
#                             update_fields=["type", "name", "created", "modified", "json_data", "updated_at"],
#                             unique_fields=["id"]
#                         )
#                         print(f"Inserted/Updated {len(batch)} CVEs from {feed}")
#                 except Exception as e:
#                     print(f"Batch insert failed for {feed}: {e}")


# import os
# import requests
# import zipfile
# import json
# from datetime import datetime
# from urllib.parse import unquote
# from django.utils.dateparse import parse_datetime
# from dashboard.models import CveNvd, CPE
# from django.db import transaction


# def extract_cpes_from_config(node):
#     """
#     Recursively extract all cpe_match entries from a node.
#     """
#     cpes = []
#     if 'cpe_match' in node:
#         cpes.extend(node['cpe_match'])
#     if 'children' in node:
#         for child in node['children']:
#             cpes.extend(extract_cpes_from_config(child))
#     return cpes


# def parse_vendor_product(cpe23uri):
#     """
#     Extract vendor and product from a standard CPE 2.3 URI.
#     Example: cpe:2.3:o:linux:linux_kernel:6.1:rc2:*:*:*:*:*:*
#     """
#     parts = cpe23uri.split(':')
#     if len(parts) >= 5:
#         vendor = unquote(parts[3])
#         product = unquote(parts[4])
#         return vendor, product
#     return "", ""


# def download_and_process_cve_feeds(years: int = 1, download_dir: str = "cve_feeds"):
#     """
#     Downloads and processes NVD CVE feeds and inserts/updates them in the CveNvd and CPE database using bulk operations.
#     """
#     base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"
#     current_year = datetime.now().year

#     feeds = [f"nvdcve-1.1-{year}.json.zip" for year in range(current_year, current_year - years, -1)]
#     feeds += ["nvdcve-1.1-recent.json.zip", "nvdcve-1.1-modified.json.zip"]

#     os.makedirs(download_dir, exist_ok=True)

#     for feed in feeds:
#         file_path = os.path.join(download_dir, feed)
#         url = f"{base_url}/{feed}"

#         if not os.path.exists(file_path):
#             print(f"Downloading {feed}...")
#             response = requests.get(url)
#             response.raise_for_status()
#             with open(file_path, "wb") as f:
#                 f.write(response.content)

#         print(f"Processing {feed}...")
#         with zipfile.ZipFile(file_path, 'r') as zip_ref:
#             json_filename = zip_ref.namelist()[0]
#             with zip_ref.open(json_filename) as json_file:
#                 data = json.load(json_file)
#                 cve_items = data.get('CVE_Items', [])

#                 cve_batch = []
#                 cpe_batch = []
#                 cpe_seen = set()

#                 for item in cve_items:
#                     try:
#                         # Process CVE
#                         cve_id = item['cve']['CVE_data_meta']['ID']
#                         cve_type = item['cve'].get('data_type', 'CVE')
#                         cve_name = cve_id
#                         published = parse_datetime(item.get('publishedDate'))
#                         modified = parse_datetime(item.get('lastModifiedDate'))

#                         cve_batch.append(CveNvd(
#                             id=cve_id,
#                             type=cve_type,
#                             name=cve_name,
#                             created=published,
#                             modified=modified,
#                             json_data=item
#                         ))

#                         # Process CPEs
#                         configurations = item.get('configurations', {}).get('nodes', [])
#                         for node in configurations:
#                             cpe_matches = extract_cpes_from_config(node)
#                             for cpe in cpe_matches:
#                                 if cpe.get("vulnerable", False):
#                                     cpe23uri = cpe.get("cpe23Uri")
#                                     if not cpe23uri or cpe23uri in cpe_seen:
#                                         continue
#                                     cpe_seen.add(cpe23uri)

#                                     vendor, product = parse_vendor_product(cpe23uri)
#                                     cpe_batch.append(CPE(
#                                         id=cpe23uri,
#                                         name=cpe23uri,
#                                         vendor=vendor,
#                                         product=product
#                                     ))

#                     except Exception as e:
#                         print(f"Skipping CVE due to error: {e}")

#                 # Insert CVEs
#                 try:
#                     with transaction.atomic():
#                         CveNvd.objects.bulk_create(
#                             cve_batch,
#                             batch_size=500,
#                             update_conflicts=True,
#                             update_fields=["type", "name", "created", "modified", "json_data", "updated_at"],
#                             unique_fields=["id"]
#                         )
#                         print(f"Inserted/Updated {len(cve_batch)} CVEs from {feed}")
#                 except Exception as e:
#                     print(f"Batch insert failed for CVEs in {feed}: {e}")

#                 # Insert CPEs
#                 try:
#                     with transaction.atomic():
#                         CPE.objects.bulk_create(
#                             cpe_batch,
#                             batch_size=500,
#                             ignore_conflicts=True
#                         )
#                         print(f"Inserted {len(cpe_batch)} new CPEs from {feed}")
#                 except Exception as e:
#                     print(f"Batch insert failed for CPEs in {feed}: {e}")


import os
import requests
import zipfile
import json
from datetime import datetime
from urllib.parse import unquote
from django.utils.dateparse import parse_datetime
from dashboard.models import CveNvd, CPE
from django.db import transaction

def extract_cpes_from_config(node):
    cpes = []
    if 'cpe_match' in node:
        cpes.extend(node['cpe_match'])
    if 'children' in node:
        for child in node['children']:
            cpes.extend(extract_cpes_from_config(child))
    return cpes

def parse_vendor_product(cpe23uri):
    parts = cpe23uri.split(':')
    if len(parts) >= 5:
        vendor = unquote(parts[3])
        product = unquote(parts[4])
        return vendor, product
    return "", ""

def download_and_process_cve_feeds(years: int = 1, download_dir: str = "cve_feeds"):
    base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"
    current_year = datetime.now().year

    feeds = [f"nvdcve-1.1-{year}.json.zip" for year in range(current_year, current_year - years, -1)]
    feeds += ["nvdcve-1.1-recent.json.zip", "nvdcve-1.1-modified.json.zip"]

    os.makedirs(download_dir, exist_ok=True)

    for feed in feeds:
        file_path = os.path.join(download_dir, feed)
        url = f"{base_url}/{feed}"

        if not os.path.exists(file_path):
            print(f"Downloading {feed}...")
            response = requests.get(url)
            response.raise_for_status()
            with open(file_path, "wb") as f:
                f.write(response.content)

        print(f"Processing {feed}...")
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            json_filename = zip_ref.namelist()[0]
            with zip_ref.open(json_filename) as json_file:
                data = json.load(json_file)
                cve_items = data.get('CVE_Items', [])

                cve_batch = []
                cpe_batch = []
                cpe_seen = set()
                cpe_cve_links = []

                for item in cve_items:
                    try:
                        # CVE Fields
                        cve_id = item['cve']['CVE_data_meta']['ID']
                        cve_type = item['cve'].get('data_type', 'CVE')
                        cve_name = cve_id
                        published = parse_datetime(item.get('publishedDate'))
                        modified = parse_datetime(item.get('lastModifiedDate'))

                        cve_batch.append(CveNvd(
                            id=cve_id,
                            type=cve_type,
                            name=cve_name,
                            created=published,
                            modified=modified,
                            json_data=item
                        ))

                        # CPE Extraction
                        configurations = item.get('configurations', {}).get('nodes', [])
                        for node in configurations:
                            cpe_matches = extract_cpes_from_config(node)
                            for cpe in cpe_matches:
                                if cpe.get("vulnerable", False):
                                    cpe23uri = cpe.get("cpe23Uri")
                                    if not cpe23uri:
                                        continue
                                    vendor, product = parse_vendor_product(cpe23uri)

                                    if cpe23uri not in cpe_seen:
                                        cpe_seen.add(cpe23uri)
                                        cpe_batch.append(CPE(
                                            id=cpe23uri,
                                            name=cpe23uri,
                                            vendor=vendor,
                                            product=product
                                        ))

                                    cpe_cve_links.append((cpe23uri, cve_id))

                    except Exception as e:
                        print(f"Skipping CVE due to error: {e}")

                # Insert CVEs
                try:
                    with transaction.atomic():
                        CveNvd.objects.bulk_create(
                            cve_batch,
                            batch_size=500,
                            update_conflicts=True,
                            update_fields=["type", "name", "created", "modified", "json_data", "updated_at"],
                            unique_fields=["id"]
                        )
                        print(f"Inserted/Updated {len(cve_batch)} CVEs from {feed}")
                except Exception as e:
                    print(f"Batch insert failed for CVEs in {feed}: {e}")

                # Insert CPEs
                try:
                    with transaction.atomic():
                        CPE.objects.bulk_create(
                            cpe_batch,
                            batch_size=500,
                            ignore_conflicts=True
                        )
                        print(f"Inserted {len(cpe_batch)} new CPEs from {feed}")
                except Exception as e:
                    print(f"Batch insert failed for CPEs in {feed}: {e}")

                # Insert CPE-CVE Links
                try:
                    through_model = CPE.cve_ids.through
                    existing_cpes = {c.id: c for c in CPE.objects.filter(id__in={cid for cid, _ in cpe_cve_links})}
                    existing_cves = {c.id: c for c in CveNvd.objects.filter(id__in={cid for _, cid in cpe_cve_links})}

                    through_batch = [
                        through_model(cpe_id=cpe_id, cvenvd_id=cve_id)
                        for cpe_id, cve_id in cpe_cve_links
                        if cpe_id in existing_cpes and cve_id in existing_cves
                    ]

                    with transaction.atomic():
                        through_model.objects.bulk_create(
                            through_batch,
                            batch_size=500,
                            ignore_conflicts=True
                        )
                        print(f"Inserted {len(through_batch)} CPE-CVE links for {feed}")
                except Exception as e:
                    print(f"Batch insert failed for CPE-CVE links in {feed}: {e}")
