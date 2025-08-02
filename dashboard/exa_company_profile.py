from exa_py import Exa
from BluHawk import load_env as myenv
from BluHawk.utils import log_exception
import re

exa = Exa(api_key = myenv.EXA_API)

def get_exa_linkedin_profile(domain, include_text = []):
    result = exa.search_and_contents(
        f"{domain} instagram profile:",
        text = True,
        livecrawl = "always",
        type = "keyword",
        num_results = 5,
        include_text = include_text,
        include_domains = ["linkedin.com"]
        )
    return result

def get_exa_youtube_profile(domain, include_text = []):
    result = exa.search_and_contents(
        f"{domain} Youtube profile:",
        text = True,
        livecrawl = "always",
        type = "keyword",
        num_results = 5,
        include_text = include_text,
        include_domains = ["youtube.com"]
        )
    return result

def get_exa_facebook_profile(domain, include_text = []):
    result = exa.search_and_contents(
        f"{domain} facebook profile:",
        text = True,
        livecrawl = "always",
        type = "keyword",
        num_results = 5,
        include_text = include_text,
        include_domains = ["facebook.com"]
        )
    return result

def get_exa_twitter_profile(domain, include_text = []):
    result = exa.search_and_contents(
        f"{domain} Twitter (X) profile:",
        type = "keyword",
        text = True,
        livecrawl = "always",
        num_results = 5,
        include_domains = ["x.com", "twitter.com"],
        include_text = include_text
    )
    return result

def get_latest_info(domain, include_text = []):
    
    result = exa.search_and_contents(
    f"{domain} News:",
    category = "news",
    type = "keyword",
    text = True,
    livecrawl = "always",
    include_text = include_text,
    exclude_domains = [domain],
    summary = True
    )
    return result

def get_company_summary(domain, include_text = []):
    result = exa.get_contents(
        [f"{domain}"],
        text = True,
        summary = True
    )
    return result

def get_subpages(domain,include_text = []):
    result = exa.search_and_contents(
        f"{domain}",
        category = "company",
        type = "neural",
        text = True,
        num_results = 1,
        livecrawl = "always",
        subpages = 10,
        subpage_target = ["about", "pricing", "faq", "blog"],
        include_domains = [f"{domain}"]
    )
    return result


def clean_company_profile(company_profile):
    lines_to_remove = [
        "Resolved Search Type: keyword",
        "CostDollars: total",
    ]
    for key, value in company_profile.items():
        if isinstance(value, str):
            processed_lines = []
            for line in value.split('\n'):
                stripped_line = line.strip()
                remove_line = False
                for prefix in lines_to_remove:
                    if stripped_line.startswith(prefix):
                        remove_line = True
                        break
                if not remove_line and stripped_line:
                    processed_lines.append(stripped_line)

            cleaned_value = '\n'.join(processed_lines)
            company_profile[key] = cleaned_value
        else:
            company_profile[key] = value
    return company_profile

def create_company_profile(domain, **kwargs):
    try:
        company_name = [kwargs.get('company_name', '')]
        company_summary = get_company_summary(domain, company_name)
        print("Fetched Company Summary fetched")
        subpages = get_subpages(domain, company_name)
        print("Fetched Subpages fetched")
        linkedin_profile = get_exa_linkedin_profile(domain, company_name)
        print("Fetched Linkedin Profile fetched")
        youtube_profile = get_exa_youtube_profile(domain, company_name)
        print("Fetched Youtube Profile fetched")
        facebook_profile = get_exa_facebook_profile(domain, company_name)
        print("Fetched Facebook Profile fetched")
        twitter_profile = get_exa_twitter_profile(domain, company_name)
        print("Fetched Twitter Profile fetched")
        latest_info = get_latest_info(domain, company_name)
        print("Fetched Latest Info fetched")

        company_profile = {
            "company_summary": str(company_summary),
            "subpages": str(subpages),
            "linkedin_profile": str(linkedin_profile),
            "youtube_profile": str(youtube_profile),
            "facebook_profile": str(facebook_profile),
            "twitter_profile": str(twitter_profile),
            "latest_info": str(latest_info)
        }

        # Clean up the company profile data

        company_profile = clean_company_profile(company_profile)
        
        return {
            "status" : "success",
            "data": company_profile
        }
    except Exception as e:
        log_exception(e)

        return {
            "status" : "error",
            "message": str(e),
            "data": None
        }