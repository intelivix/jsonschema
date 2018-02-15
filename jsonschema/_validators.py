import re

from jsonschema import _utils
from jsonschema.exceptions import FormatError, ValidationError
from jsonschema.compat import iteritems


def patternProperties(validator, patternProperties, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for pattern, subschema in iteritems(patternProperties):
        for k, v in iteritems(instance):
            if re.search(pattern, k):
                for error in validator.descend(
                    v, subschema, path=k, schema_path=pattern,
                ):
                    yield error


def propertyNames(validator, propertyNames, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for property in instance:
        for error in validator.descend(
            instance=property,
            schema=propertyNames,
        ):
            yield error


def additionalProperties(validator, aP, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    extras = set(_utils.find_additional_properties(instance, schema))

    if validator.is_type(aP, "object"):
        for extra in extras:
            for error in validator.descend(instance[extra], aP, path=extra):
                yield error
    elif not aP and extras:
        if "patternProperties" in schema:
            patterns = sorted(schema["patternProperties"])
            if len(extras) == 1:
                verb = "does"
            else:
                verb = "do"
            error = "{!s} {!s} not match any of the regexes: {!s}".format(
                ", ".join(map(repr, sorted(extras))),
                verb,
                ", ".join(map(repr, patterns)),
            )
            yield ValidationError(error)
        else:
            error = "Additional properties are not allowed (%s %s unexpected)"
            yield ValidationError(error % _utils.extras_msg(extras))


def items(validator, items, instance, schema):
    if not validator.is_type(instance, "array"):
        return

    if validator.is_type(items, "array"):
        for (index, item), subschema in zip(enumerate(instance), items):
            for error in validator.descend(
                item, subschema, path=index, schema_path=index,
            ):
                yield error
    else:
        for index, item in enumerate(instance):
            for error in validator.descend(item, items, path=index):
                yield error


def additionalItems(validator, aI, instance, schema):
    if (
        not validator.is_type(instance, "array") or
        validator.is_type(schema.get("items", {}), "object")
    ):
        return

    len_items = len(schema.get("items", []))
    if validator.is_type(aI, "object"):
        for index, item in enumerate(instance[len_items:], start=len_items):
            for error in validator.descend(item, aI, path=index):
                yield error
    elif not aI and len(instance) > len(schema.get("items", [])):
        error = "Additional items are not allowed (%s %s unexpected)"
        yield ValidationError(
            error %
            _utils.extras_msg(instance[len(schema.get("items", [])):])
        )


def const(validator, const, instance, schema):
    if instance != const:
        yield ValidationError("%r was expected" % (const,))


def contains(validator, contains, instance, schema):
    if not validator.is_type(instance, "array"):
        return

    if not any(validator.is_valid(element, contains) for element in instance):
        yield ValidationError(
            "None of %r are valid under the given schema" % (instance,)
        )


def exclusiveMinimum(validator, minimum, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if instance <= minimum:
        yield ValidationError(
            "%r is less than or equal to the minimum of %r" % (
                instance, minimum,
            ),
        )


def exclusiveMaximum(validator, maximum, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if instance >= maximum:
        yield ValidationError(
            "{!r} is {!s} the minimum of {!r}".format(instance, cmp, minimum)
        )


def minimum(validator, minimum, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if instance < minimum:
        yield ValidationError(
            "%r is less than the minimum of %r" % (instance, minimum)
        )


def maximum(validator, maximum, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if instance > maximum:
        yield ValidationError(
            "{!r} is {!s} the maximum of {!r}".format(instance, cmp, maximum)
        )


def multipleOf(validator, dB, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if isinstance(dB, float):
        quotient = instance / dB
        failed = int(quotient) != quotient
    else:
        failed = instance % dB

    if failed:
        yield ValidationError("{!r} is not a multiple of {!r}".format(instance, dB))


def minItems(validator, mI, instance, schema):
    if validator.is_type(instance, "array") and len(instance) < mI:
        yield ValidationError("{!r} is too short".format(instance))


def maxItems(validator, mI, instance, schema):
    if validator.is_type(instance, "array") and len(instance) > mI:
        yield ValidationError("{!r} is too long".format(instance))


def uniqueItems(validator, uI, instance, schema):
    if (
        uI and
        validator.is_type(instance, "array") and
        not _utils.uniq(instance)
    ):
        yield ValidationError("{!r} has non-unique elements".format(instance))


def pattern(validator, patrn, instance, schema):
    if (
        validator.is_type(instance, "string") and
        not re.search(patrn, instance)
    ):
        yield ValidationError("{!r} does not match {!r}".format(instance, patrn))


def format(validator, format, instance, schema):
    if validator.format_checker is not None:
        try:
            validator.format_checker.check(instance, format)
        except FormatError as error:
            yield ValidationError(error.message, cause=error.cause)


def minLength(validator, mL, instance, schema):
    if validator.is_type(instance, "string") and len(instance) < mL:
        yield ValidationError("{!r} is too short".format(instance))


def maxLength(validator, mL, instance, schema):
    if validator.is_type(instance, "string") and len(instance) > mL:
        yield ValidationError("{!r} is too long".format(instance))


def dependencies(validator, dependencies, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for E, dependency in iteritems(dependencies):
        if property not in instance:
            continue

        if validator.is_type(dependency, "array"):
            for each in dependency:
                if each not in instance:
                    message = "%r is a dependency of %r"
                    yield ValidationError(message % (each, property))
        else:
            for error in validator.descend(
                instance, dependency, schema_path=property,
            ):
                yield error



def enum(validator, enums, instance, schema):
    if instance not in enums:
        yield ValidationError("{!r} is not one of {!r}".format(instance, enums))


def ref(validator, ref, instance, schema):
    resolve = getattr(validator.resolver, "resolve", None)
    if resolve is None:
        with validator.resolver.resolving(ref) as resolved:
            for error in validator.descend(instance, resolved):
                yield error
    else:
        scope, resolved = validator.resolver.resolve(ref)
        validator.resolver.push_scope(scope)

        try:
            for error in validator.descend(instance, resolved):
                yield error
        finally:
            validator.resolver.pop_scope()


def type(validator, types, instance, schema):
    types = _utils.ensure_list(types)

    if not any(validator.is_type(instance, type) for type in types):
        yield ValidationError(_utils.types_msg(instance, types))


def type_draft3(validator, types, instance, schema):
    types = _utils.ensure_list(types)

    all_errors = []
    for index, type in enumerate(types):
        if type == "any":
            return
        if validator.is_type(type, "object"):
            errors = list(validator.descend(instance, type, schema_path=index))
            if not errors:
                return
            all_errors.extend(errors)
        else:
            if validator.is_type(instance, type):
                return
    else:
        yield ValidationError(
            _utils.types_msg(instance, types), context=all_errors,
        )


def properties_draft3(validator, properties, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for prop, subschema in iteritems(properties):
        if prop in instance:
            for error in validator.descend(
                instance[prop],
                subschema,
                path=prop,
                schema_path=prop,
            ):
                yield error
        elif subschema.get("required", False):
            error = ValidationError("{!r} is a required property".format(prop))
            error._set(
                validator="required",
                validator_value=subschema["required"],
                instance=instance,
                schema=schema,
            )
            error.path.appendleft(prop)
            error.schema_path.extend([prop, "required"])
            yield error


def disallow_draft3(validator, disallow, instance, schema):
    for disallowed in _utils.ensure_list(disallow):
        if validator.is_valid(instance, {"type": [disallowed]}):
            yield ValidationError(
                "{!r} is disallowed for {!r}".format(disallowed, instance)
            )


def extends_draft3(validator, extends, instance, schema):
    if validator.is_type(extends, "object"):
        for error in validator.descend(instance, extends):
            yield error
        return
    for index, subschema in enumerate(extends):
        for error in validator.descend(instance, subschema, schema_path=index):
            yield error


def type_draft4(validator, types, instance, schema):
    types = _utils.ensure_list(types)

    if not any(validator.is_type(instance, type) for type in types):
        yield ValidationError(_utils.types_msg(instance, types))


def properties(validator, properties, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for prop, subschema in iteritems(properties):
        if prop in instance:
            for error in validator.descend(
                instance[prop],
                subschema,
                path=prop,
                schema_path=prop,
            ):
                yield error


def required(validator, required, instance, schema):
    if not validator.is_type(instance, "object"):
        return
    for prop in required:
        if prop not in instance:
            yield ValidationError("{!r} is a required property".format(prop))


def minProperties(validator, mP, instance, schema):
    if validator.is_type(instance, "object") and len(instance) < mP:
        yield ValidationError(
            "{!r} does not have enough properties".format(instance)
        )


def maxProperties(validator, mP, instance, schema):
    if not validator.is_type(instance, "object"):
        return
    if validator.is_type(instance, "object") and len(instance) > mP:
        yield ValidationError("{!r} has too many properties".format(instance))


def allOf(validator, allOf, instance, schema):
    for index, subschema in enumerate(allOf):
        for error in validator.descend(instance, subschema, schema_path=index):
            yield error


def anyOf(validator, anyOf, instance, schema):
    all_errors = []
    for index, subschema in enumerate(anyOf):
        errs = list(validator.descend(instance, subschema, schema_path=index))
        if not errs:
            break
        all_errors.extend(errs)
    else:
        yield ValidationError(
            "{!r} is not valid under any of the given schemas".format(instance),
            context=all_errors,
        )

    more_valid = [s for i, s in subschemas if validator.is_valid(instance, s)]
    if more_valid:
        more_valid.append(first_valid)
        reprs = ", ".join(repr(schema) for schema in more_valid)
        yield ValidationError(
            "{!r} is valid under each of {!s}".format(instance, reprs)
        )


def oneOf(validator, oneOf, instance, schema):
    subschemas = enumerate(oneOf)
    all_errors = []
    for index, subschema in subschemas:
        errs = list(validator.descend(instance, subschema, schema_path=index))
        if not errs:
            first_valid = subschema
            break
        all_errors.extend(errs)
    else:
        yield ValidationError(
            "{!r} is not valid under any of the given schemas".format(instance),
            context=all_errors,
        )

    more_valid = [s for i, s in subschemas if validator.is_valid(instance, s)]
    if more_valid:
        more_valid.append(first_valid)
        reprs = ", ".join(repr(schema) for schema in more_valid)
        yield ValidationError(
            "%r is valid under each of %s" % (instance, reprs)
        )


def not_(validator, not_schema, instance, schema):
    if validator.is_valid(instance, not_schema):
        yield ValidationError(
            "{!r} is not allowed for {!r}".format(not_schema, instance)
        )


def if_(validator, if_schema, instance, schema):
    if validator.is_valid(instance, if_schema):
        if u"then" in schema:
            then = schema[u"then"]
            for error in validator.descend(instance, then, schema_path="then"):
                yield error
    elif u"else" in schema:
        else_ = schema[u"else"]
        for error in validator.descend(instance, else_, schema_path="else"):
            yield error


def required_with_list(validator, required, instance, schema):
    if not validator.is_type(instance, "object"):
        return
    for prop in required:
        if isinstance(prop, list):
            if not any([instance.get(x, False) for x in prop]):
                yield ValidationError("At least one of {!r} are "
                                      "required".format(prop))
        elif prop not in instance:
            yield ValidationError("{!r} is a required property".format(prop))


def properties_with_default(validator, properties, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for prop, subschema in iteritems(properties):
        if prop in instance:
            for error in validator.descend(
                instance[prop],
                subschema,
                path=prop,
                schema_path=prop,
            ):
                yield error

    # Default is assigned after properties validation so that type errors
    # aren't reported if the default type doesn't match it's property type
    for prop, subschema in properties.iteritems():
        if "default" in subschema:
            instance.setdefault(prop, subschema["default"])
