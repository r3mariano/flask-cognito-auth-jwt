from flask import jsonify
from werkzeug.local import LocalProxy


# jsonify wrapper so we can switch out easily
def build_response(obj):
    obj_to_build = obj
    if isinstance(obj, LocalProxy):
        obj_to_build = obj._get_current_object()
    return jsonify(obj_to_build)
