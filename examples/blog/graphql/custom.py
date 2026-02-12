from graphql import parse, validate, build_schema, GraphQLError, specified_rules
from graphql.validation import NoSchemaIntrospectionCustomRule

from flask import request

dummy_schema = build_schema("""type Query { name: String }""")
validation_rules = specified_rules + (NoSchemaIntrospectionCustomRule,)

def graphql_trap(req):
    body = request.get_json(silent=True) or {}
    query = body.get("query", "")

    try:
        ast = parse(query)
    except GraphQLError as e:
        return {"data": None, "errors": [e.formatted]}

    errors = validate(dummy_schema, ast, rules=validation_rules)
    if errors:
        return {"data": None, "errors": [errors[0].formatted]}

    return {"data": None}
