import json
import schemathesis, schemathesis.schemas
from schemathesis.specs.openapi.schemas import BaseOpenAPISchema
from schemathesis import Case
from schemathesis.transports.responses import GenericResponse


@schemathesis.hook
def before_call(context, case: Case):
    if case.path == '/api/v1/attack-mobile/objects/':
        case.query['attack_type'] = "Technique"

@schemathesis.hook
def after_load_schema(
    context: schemathesis.hooks.HookContext,
    schema: BaseOpenAPISchema,
) -> None:
    
    schema.add_link(
        source=schema["/api/v1/jobs/"]['GET'],
        target=schema["/api/v1/jobs/{job_id}/"]['GET'],
        status_code=200,
        parameters={"path.job_id": '$response.body#/jobs/0/id'}
    )
    for matrix in ['enterprise', 'ics', 'mobile']:
        for path in ['', 'bundle/', 'relationships/', 'versions/']:
            schema.add_link(
                source=schema[f"/api/v1/attack-{matrix}/objects/"]['GET'],
                target=schema[f"/api/v1/attack-{matrix}/objects/{{attack_id}}/{path}"]['GET'],
                status_code=200,
                parameters={"path.attack_id": '$response.body#/objects/0/external_references/0/external_id'}
            )

    for op in ["location", "atlas", "disarm"]:
        for path in ['', 'bundle/', 'relationships/', 'versions/']:
            id_param = op + '_id'
            id_param_str = '{'+id_param+'}'
            schema.add_link(
                source=schema[f"/api/v1/{op}/objects/"]['GET'],
                target=schema[f"/api/v1/{op}/objects/{id_param_str}/{path}"]['GET'],
                status_code=200,
                parameters={f"path.{id_param}": '$response.body#/objects/0/external_references/0/external_id'}
            )