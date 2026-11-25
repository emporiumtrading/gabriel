"""Comparison candidates; registry membership never admits production inference."""
from decimal import Decimal, InvalidOperation

from gabriel.identity.model_evaluation import digest

VERSION='provider-candidate-routes-v2'
ROUTES={
    'openai/gpt-4.1-mini':('Azure','azure','max_completion_tokens',None),
    'qwen/qwen3.5-35b-a3b':('DeepInfra','deepinfra/fp8','max_tokens','disabled'),
    'mistralai/mistral-small-3.2-24b-instruct':('Mistral','mistral/eu','max_tokens',None),
    'nvidia/nemotron-3-super-120b-a12b':('Crusoe','crusoe/fp8','max_tokens','disabled'),
    'openai/gpt-oss-120b':('Cerebras','cerebras/fp16','max_tokens','low'),
    'meta-llama/llama-3.3-70b-instruct':('Cloudflare','cloudflare/fp8','max_tokens',None),
    'deepseek/deepseek-v3.2':('SiliconFlow','siliconflow/fp8','max_tokens','disabled'),
    'qwen/qwen3.5-122b-a10b':('SiliconFlow','siliconflow/fp8','max_tokens','disabled'),
}
# Only a reviewed release can populate exact configuration digests. An account
# balance, cheap route, registry entry or operator quote cannot supply admission.
PRODUCTION_CONFIGURATIONS=frozenset()

# These are the bounded model identifiers Gabriel may send directly to
# DeepInfra. The remaining catalog entries are OpenRouter-routed comparison
# candidates and must not silently switch providers.
DEEPINFRA_MODELS=frozenset({'openai/gpt-oss-120b','qwen/qwen3.5-35b-a3b'})
DEEPINFRA_IDS={
    'openai/gpt-oss-120b':'openai/gpt-oss-120b',
    'qwen/qwen3.5-35b-a3b':'Qwen/Qwen3.5-35B-A3B',
}


class RouteError(ValueError):
    pass


def price(value):
    try:
        if type(value) not in {str,int,float}: raise ValueError
        result=Decimal(str(value))
        if not result.is_finite() or result<0: raise ValueError
        return result
    except (ValueError,InvalidOperation):
        raise RouteError('invalid_route_price') from None


def eligible(catalog,model):
    if model not in ROUTES: raise RouteError('unknown_candidate_route')
    data=catalog.get('data') if isinstance(catalog,dict) else None
    if not isinstance(data,list) or len(data)>10000: raise RouteError('invalid_zdr_catalog')
    provider,tag,token_parameter,reasoning=ROUTES[model]
    matches=[r for r in data if isinstance(r,dict) and r.get('model_id')==model
             and r.get('provider_name')==provider and r.get('tag')==tag
             and type(r.get('status')) is int and r['status']==0]
    if len(matches)!=1: raise RouteError('candidate_zdr_route_unavailable')
    row=matches[0]
    supported=row.get('supported_parameters')
    required={'temperature','response_format',token_parameter}|({'reasoning'} if reasoning else set())
    if not isinstance(supported,list) or not required<=set(supported):
        raise RouteError('candidate_parameters_unavailable')
    pricing=row.get('pricing')
    if not isinstance(pricing,dict): raise RouteError('invalid_route_price')
    incoming,outgoing=price(pricing.get('prompt')),price(pricing.get('completion'))
    if incoming>Decimal('0.0000005') or outgoing>Decimal('0.000003') or price(pricing.get('request',0))!=0:
        raise RouteError('candidate_price_exceeds_limit')
    return dict(model=model,provider=provider,tag=tag,input_usd_per_token=str(incoming),
                output_usd_per_token=str(outgoing),catalog_digest=digest(row),
                catalog_classification='openrouter_reported_zdr_not_independent_attestation',
                quality_qualified=False,production_admission=False)


def upstream_model(model, provider='openrouter'):
    if model not in ROUTES: raise RouteError('unknown_candidate_route')
    if provider=='openrouter': return model
    if provider=='deepinfra' and model in DEEPINFRA_IDS: return DEEPINFRA_IDS[model]
    raise RouteError('provider_model_not_admitted')


def parameters(model, provider='openrouter'):
    if model not in ROUTES: raise RouteError('unknown_candidate_route')
    upstream_model(model,provider)
    _,tag,token_parameter,reasoning=ROUTES[model]
    result=dict(temperature=0,stream=False,response_format={'type':'json_object'},
                provider=dict(only=[tag],allow_fallbacks=False,require_parameters=True,
                              data_collection='deny',zdr=True,
                              max_price=dict(prompt=0.5,completion=3,request=0)) if provider=='openrouter' else None)
    if provider=='deepinfra': result.pop('provider')
    result[token_parameter]=768
    if reasoning and provider=='openrouter': result['reasoning']={'enabled':False} if reasoning=='disabled' else {'effort':'low'}
    elif reasoning=='low' and provider=='deepinfra': result['reasoning_effort']='low'
    return result


def deepinfra_eligible(catalog,model):
    """Require the exact direct model id in DeepInfra's current catalog."""
    expected=upstream_model(model,'deepinfra')
    data=catalog.get('data') if isinstance(catalog,dict) else None
    if not isinstance(data,list) or len(data)>10000:
        raise RouteError('deepinfra_model_catalog_invalid')
    if not any(isinstance(row,dict) and row.get('id')==expected for row in data):
        raise RouteError('deepinfra_model_unavailable')
    return dict(model=model,provider='DeepInfra',model_id=expected,
                catalog_classification='deepinfra_reported_model_catalog',production_admission=False)
