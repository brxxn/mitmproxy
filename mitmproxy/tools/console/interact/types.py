import json

class InteractCondition:

    def __init__(self, object) -> None:
        self.type: str = object['type']
        self.operator: str = object['operator']
        self.value: str = object['value']

    def to_dict(self) -> dict:
        return {
            'type': self.type,
            'operator': self.operator,
            'value': self.value
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
class InteractAction:

    def __init__(self, object) -> None:
        self.type: str = object['type']
        self.arguments: dict = object['arguments']

    def to_dict(self) -> dict:
        return {
            'type': self.type,
            'arguments': self.arguments
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

class InteractRule:

    def __init__(self, object) -> None:
        self.name: str = object['name']
        self.type: str = object['type']
        self.enabled: bool = object['enabled']
        self.all_conditions_required: bool = object['all_conditions_required']
        self.conditions: list[InteractCondition] = [InteractCondition(c) for c in object['conditions']]
        self.actions: list[InteractAction] = [InteractAction(a) for a in object['actions']]

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'type': self.type,
            'enabled': self.enabled,
            'all_conditions_required': self.all_conditions_required,
            'conditions': [c.to_dict() for c in self.conditions],
            'actions': [a.to_dict() for a in self.actions]
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())

def interact_rule_from_json(input_str: str) -> InteractRule:
    rule_dict = json.loads(input_str)
    return InteractRule(rule_dict)