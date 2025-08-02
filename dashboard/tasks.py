from celery import shared_task
import logging
from dashboard.models import MitreAttackEntity as mit_entity, MitreEntityRelation as relation,  Subscribers, Misp
import traceback
import gc
from datetime import datetime, timezone

import requests
from dateutil import parser as dateutil_parser
from BluHawk import load_env as myenv

TAXII_BASE_URL = 'https://attack-taxii.mitre.org/api/v21'
HEADERS = {'Accept': 'application/taxii+json;version=2.1'}
TIMEOUT = 30
ENTITY_TYPES = {'attack-pattern', 'campaign', 'course-of-action', 
               'intrusion-set', 'malware', 'tool', 'x-mitre-tactic'}

MISP_SOURCES = {
    "android": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/android.json",
    "botnet": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/botnet.json",
    "attck4fraud": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/attck4fraud.json",
    "banker": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/banker.json",
    "malpedia": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json",
    "tools": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/tool.json"
}

logger = logging.getLogger('celery')

def get_mitre_id(external_references):
    for ref in (external_references or []):
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id')
    return None

from dateutil import parser as dateutil_parser
from datetime import datetime, timezone

import dateutil.parser

def normalize_datetime(dt):
    if isinstance(dt, str):
        return dateutil.parser.isoparse(dt).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


def refreshMitreData():
    try:
        url = 'https://attack-taxii.mitre.org/api/v21/collections'
        headers = {
            'Accept': 'application/taxii+json;version=2.1'
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            # Batch collections
            collections = response.json().get('collections', [])
            relations_batch = []
            mitre_entities_batch = []
            updated_entities = set()
            
            for collection in collections:
                collection_id = collection.get('id')
                objects_url = f"https://attack-taxii.mitre.org/api/v21/collections/{collection_id}/objects"
                objects_response = requests.get(objects_url, headers=headers)

                if objects_response.status_code == 200:
                    objects = objects_response.json().get('objects', [])
                    
                    for obj in objects:
                        obj_id = obj.get('id')
                        
                        if obj.get('type') == 'relationship':
                            try:
                                relations_batch.append(
                                    relation(
                                        id=obj_id,
                                        type=obj.get('type'),
                                        modified=obj.get('modified'),
                                        created=obj.get('created'),
                                        json_data=obj,
                                        relationship_type=obj.get('relationship_type'),
                                        source_ref=obj.get('source_ref'),
                                        target_ref=obj.get('target_ref')
                                    )
                                )
                            except Exception as e:
                                print("Error processing relationship:", str(e))
                        
                        elif obj.get('type') in ['attack-pattern', 'campaign', 'course-of-action', 
                                               'intrusion-set', 'malware', 'tool', 'x-mitre-tactic']:
                            try:
                                obj_mitre_id = None
                                for ref in obj.get('external_references', []):
                                    if ref.get('source_name', '').lower().startswith('mitre'):
                                        obj_mitre_id = ref.get('external_id')
                                        break
                                
                                if obj_mitre_id is None:
                                    print(f"Object {obj_id} does not have a valid mitre id")
                                
                                # Check if modification is needed
                                existing_entity = mit_entity.objects.filter(id=obj_id).first()
                                requires_update = (
                                    not existing_entity or 
                                    normalize_datetime(existing_entity.modified) != normalize_datetime(obj.get('modified'))
                                )

                                if (obj_mitre_id or  obj_id):
                                
                                    mitre_entities_batch.append(
                                        mit_entity(
                                            id=obj_id,
                                            name=obj.get('name'),
                                            type=obj.get('type'),
                                            modified=obj.get('modified'),
                                            created=obj.get('created'),
                                            json_data=obj,
                                            target=collection.get('title'),
                                            target_id=collection_id,
                                            mitre_object_id=obj_mitre_id if obj_mitre_id else obj_id
                                        )
                                    )
                                    
                                    if requires_update:
                                        updated_entities.add(obj_id)
                               
                            except Exception as e:
                                print(f"Error processing entity {obj_id}:", str(e))
                    
                    # Batch process relationships
                    if relations_batch:
                        relation.objects.bulk_create(
                            relations_batch,
                            update_conflicts=True,
                            update_fields=['type', 'modified', 'created', 'json_data', 
                                         'relationship_type', 'source_ref', 'target_ref'],
                            unique_fields=['id']
                        )
                        relations_batch = []
                    
                    # Batch process MITRE entities
                    if mitre_entities_batch:
                        mit_entity.objects.bulk_create(
                            mitre_entities_batch,
                            update_conflicts=True,
                            update_fields=['name', 'type', 'modified', 'created', 'json_data',
                                         'target', 'target_id', 'mitre_object_id'],
                            unique_fields=['id']
                        )
                        mitre_entities_batch = []
                    
                    del objects_response
                    gc.collect()
                    print({
                        "message": f"Processed collection {collection.get('title')}",
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'status': 'success'
                    })
                else:
                    print(f"Error fetching objects for collection {collection_id}: {objects_response.status_code}")
        
            # Send batched notifications
            if updated_entities:
                subscribers = Subscribers.objects.filter(entity_id__in=updated_entities)
                email_groups = {}
                
                for sub in subscribers:
                    email_groups.setdefault(sub.entity_id, []).append(sub.email)
                
                for entity_id, emails in email_groups.items():
                    try:
                        entity = mit_entity.objects.get(id=entity_id)
                        send_mail_to_subscribers(emails, entity.name)
                    except mit_entity.DoesNotExist:
                        print(f"Entity {entity_id} not found for notification")
            
            return {
                "message": "Refresh completed",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "success",
                "updated_entities": len(updated_entities)
            }
        else:
            error_msg = f"Failed to fetch collections: {response.status_code}"
            print(error_msg)
            return error_msg
            
    except Exception as e:
        error_msg = f"Error in refreshMitreData: {str(e)}"
        print(error_msg)
        return error_msg
    finally:
        gc.collect()
        logger.info("Mitre data refresh completed.")

def send_batch_notifications(entity_ids):
    try:
        subscribers = Subscribers.objects.filter(entity_id__in=entity_ids)
        email_groups = {}
        
        for sub in subscribers:
            email_groups.setdefault(sub.entity_id, []).append(sub.email)
        
        for entity_id, emails in email_groups.items():
            try:
                entity = mit_entity.objects.get(id=entity_id)
                send_mail_to_subscribers.delay(emails, entity.name)
            except mit_entity.DoesNotExist:
                logger.warning(f"Entity {entity_id} not found for notification")

    except Exception as e:
        logger.error(f"Batch notification failed: {str(e)}", exc_info=True)

def send_mail_to_subscribers(emails, entity_name):
    """Async email sending task"""
    from django.core.mail import send_mail
    from django.template.loader import render_to_string
    
    try:
        subject = 'MITRE Data Updated'
        html_content = render_to_string('subscriber_update.html', {
            'entity_name': entity_name
        })
        
        send_mail(
            subject=subject,
            message='',
            from_email=myenv.ADMIN_EMAIL,
            auth_user=myenv.EMAIL_HOST_USER,
            auth_password=myenv.EMAIL_HOST_PASSWORD,
            recipient_list=emails,
            html_message=html_content,
            fail_silently=False
        )
        logger.info(f"Sent notifications for {entity_name} to {len(emails)} subscribers")
    except Exception as e:
        logger.error(f"Email send failed: {str(e)}", exc_info=True)

def get_misp_data(url):
    """Fetch MISP data from URL with error handling"""
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch {url}: {str(e)}")
        return None

def process_misp_entry(entry, entity_type):
    """Process individual MISP entry and update database"""
    try:
        uuid = entry.get('uuid')
        if not uuid:
            return False

        Misp.objects.update_or_create(
            id=uuid,
            defaults={
                'name': entry.get('value', ''),
                'type': entity_type,
                'source_type': 'MISP',
                'json_data': entry
            }
        )
        return True
    except Exception as e:
        logger.error(f"Error processing entry {uuid}: {str(e)}")
        return False

def refresh_misp_data():
    results = {
        'processed': 0,
        'errors': 0,
        'sources': {}
    }

    for entity_type, url in MISP_SOURCES.items():
        try:
            logger.info(f"Processing {entity_type} from {url}")
            data = get_misp_data(url)
            
            if not data or 'values' not in data:
                results['sources'][entity_type] = 'failed'
                results['errors'] += 1
                continue

            success_count = 0
            error_count = 0
            
            for entry in data.get('values', []):
                if process_misp_entry(entry, entity_type):
                    success_count += 1
                else:
                    error_count += 1

            results['processed'] += success_count
            results['errors'] += error_count
            results['sources'][entity_type] = {
                'success': success_count,
                'errors': error_count
            }

            logger.info(f"Completed {entity_type}: {success_count} entries, {error_count} errors")

        except Exception as e:
            logger.error(f"Critical error processing {entity_type}: {str(e)}")
            results['errors'] += 1
            results['sources'][entity_type] = 'failed'

    results['timestamp'] = datetime.now()
    results['status'] = 'success' if results['errors'] == 0 else 'partial'
    gc.collect()
    return results