// i know that this whole thing is very hacky, but it works and is better than
// making scripts to do all of these things for me.

const ACTION_INPUT_BODY_MAP = {
    set_request_url: [
        {
            type: 'text',
            label: 'URL',
            id_prefix: 'action-request-url',
            argument: 'url'
        }
    ],
    set_request_body: [
        {
            type: 'textarea',
            label: 'Request body',
            id_prefix: 'action-request-body',
            argument: 'body'
        }
    ],
    set_request_header: [
        {
            type: 'text',
            label: 'Name',
            id_prefix: 'action-header-name',
            argument: 'name'
        },
        {
            type: 'text',
            label: 'Value',
            id_prefix: 'action-header-value',
            argument: 'value'
        }
    ],
    set_request_method: [
        {
            type: 'text',
            label: 'Method',
            id_prefix: 'action-request-method',
            argument: 'method'
        }
    ],
    set_response_body: [
        {
            type: 'textarea',
            label: 'Response body',
            id_prefix: 'action-response-body',
            argument: 'body'
        }
    ],
    set_response_header: [
        {
            type: 'text',
            label: 'Name',
            id_prefix: 'action-header-name',
            argument: 'name'
        },
        {
            type: 'text',
            label: 'Value',
            id_prefix: 'action-header-value',
            argument: 'value'
        }
    ],
    set_response_status: [
        {
            type: 'text',
            label: 'Status code',
            id_prefix: 'action-response-status',
            argument: 'status'
        }
    ],
    replace_request_url: [
        {
            type: 'text',
            label: 'Regex to match',
            id_prefix: 'action-request-regex',
            argument: 'regex'
        },
        {
            type: 'text',
            label: 'Value',
            id_prefix: 'action-request-content',
            argument: 'value'
        }
    ],
    replace_request_body: [
        {
            type: 'text',
            label: 'Regex to match',
            id_prefix: 'action-request-regex',
            argument: 'regex'
        },
        {
            type: 'textarea',
            label: 'Value',
            id_prefix: 'action-request-content',
            argument: 'value'
        }
    ],
    replace_response_body: [
        {
            type: 'text',
            label: 'Regex to match',
            id_prefix: 'action-response-regex',
            argument: 'regex'
        },
        {
            type: 'textarea',
            label: 'Value',
            id_prefix: 'action-response-content',
            argument: 'value'
        }
    ]
};

const demoRule = {
    name: 'test-rule',
    type: 'request',
    all_conditions_required: false,
    conditions: [
        {
            type: 'request_host',
            operator: 'is',
            value: 'graph.facebook.com'
        },
        {
            type: 'request_url',
            operator: 'contains',
            value: '/graphql'
        }
    ],
    actions: [
        {
            type: 'set_request_header',
            arguments: {
                name: 'header-name',
                value: 'test'
            }
        },
        {
            type: 'set_response_header',
            arguments: {
                name: 'content-type',
                value: 'text/html; charset=utf-8'
            }
        },
        {
            type: 'set_response_body',
            arguments: {
                body: 'test'
            }
        }
    ]
};

let rules = [];
let currentRule = null;
let originalRule = null;
let currentRuleIndex = -1;

// let currentRule = demoRule;

let unauthenticated = false;

const createNewRule = () => {
    originalRule = {
        name: '',
        type: 'request',
        all_conditions_required: false,
        conditions: [],
        actions: []
    };
    currentRule = originalRule;
    currentRuleIndex = -1;
    updateRuleList();
    renderRule();
}

const setActiveRule = (index) => {
    if (currentRuleIndex === index) {
        return;
    }
    originalRule = rules[index];
    currentRule = rules[index];
    currentRuleIndex = index;
    updateRuleList();
    renderRule();
}

const updateRuleList = () => {
    const ruleListNode = document.getElementById(`rule-list`);
    ruleListNode.innerHTML = '';
    for (const ruleIndex in rules) {
        const rule = rules[ruleIndex];
        let ruleLinkNode = document.createElement('a');
        ruleLinkNode.href = '#';
        if (currentRule && currentRule.name === rule.name) {
            ruleLinkNode.classList.add('active-rule-link');
        }
        ruleLinkNode.classList.add('rule-link');
        ruleLinkNode.innerText = rule.name;
        let containerNode = document.createElement('li');
        if (currentRule && currentRule.name === rule.name) {
            containerNode.classList.add('active-rule-list-item');
        }
        containerNode.classList.add('rule-list-item');
        containerNode.appendChild(ruleLinkNode);
        containerNode.onclick = () => {
            setActiveRule(ruleIndex);
        };
        ruleListNode.appendChild(containerNode);
    }
}

const getToken = () => {
    return window.localStorage.getItem('authToken') ?? '';
}

const setToken = (token) => {
    window.localStorage.setItem('authToken', token);
}

const activateUnauthenticatedState = () => {
    window.localStorage.removeItem('authToken');
    unauthenticated = true;
    window.history.pushState(null, null, '/unauthenticated');
    renderRule();
}

const processErrorResponse = async (response) => {
    if (response.status === 401 || response.status === 403) {
        console.error('invalid authentication');
        activateUnauthenticatedState();
        return null;
    }
    console.error(`failed to process request with status ${response.status} and content type ${request.headers.get('content-type')}.`);
    return null;
}

const makeGetRequest = async (url) => {
    const response = await fetch(url, {
        headers: {
            authorization: getToken()
        }
    });
    if (response.status !== 200 || !response.headers.get('content-type').includes('json')) {
        return await processErrorResponse(response);
    }
    return await response.json();
}

const makePostRequest = async (url, body) => {
    const response = await fetch(url, {
        headers: {
            authorization: getToken(),
            'content-type': 'application/json'
        },
        method: 'POST',
        body: JSON.stringify(body)
    });
    if (response.status !== 200 || !response.headers.get('content-type').includes('json')) {
        return await processErrorResponse(response);
    }
    return await response.json();
}

const addCondition = () => {
    if (!currentRule) return;
    currentRule.conditions.push({
        type: 'request_url',
        operator: 'contains',
        value: ''
    });
    renderRule();
}

const clearConditions = () => {
    if (!currentRule) return;
    currentRule.conditions = [];
    renderRule();
}

const addAction = () => {
    if (!currentRule) return;
    currentRule.actions.push({
        type: 'set_response_body',
        arguments: {
            body: ''
        }
    });
    renderRule();
}

const clearActions = () => {
    if (!currentRule) return;
    currentRule.actions = [];
    renderRule();
}

const updateRuleEnabled = () => {
    currentRule.enabled = document.getElementById(`rule-enabled`).checked;
}

const updateRuleName = () => {
    currentRule.name = document.getElementById(`rule-name`).value;
}

const updateRuleType = () => {
    currentRule.type = document.getElementById(`rule-type`).value;
}

const updateAllConditionsRequired = () => {
    currentRule.all_conditions_required = document.getElementById(`conditions-all-required`).checked;
}

const updateConditionAttribute = (index) => {
    const conditionType = document.getElementById(`condition-type-${index}`).value;
    if (conditionType === 'delete') {
        currentRule.conditions.splice(index, 1);
        renderRule();
        return;
    }
    currentRule.conditions[index].type = conditionType;
}

const updateConditionOperator = (index) => {
    currentRule.conditions[index].operator = document.getElementById(`condition-operator-${index}`).value;
}

const updateConditionValue = (index) => {
    currentRule.conditions[index].value = document.getElementById(`condition-value-${index}`).value;
}

const generateCondition = (index) => {
    if (isNaN(index)) {
        return null;
    }
    let rootElement = document.createElement('div');
    rootElement.id = `conditon-${index}`;
    rootElement.classList.add('mb-3');
    rootElement.innerHTML = `<form class="row gy-2 gx-3 align-items-center">
        <div class="col-auto">
            <label for="condition-type-${index}" class="form-label">Attribute</label>
            <select class="form-select" id="condition-type-${index}" onchange="updateConditionAttribute(${index})">
                <option value="request_url">Request URL</option>
                <option value="request_host">Request Host</option>
                <option value="request_body">Request Body</option>
                <option value="response_status_code">Response Status Code</option>
                <option value="response_content_type">Response Content Type</option>
                <option value="response_body">Response Body</option>
                <option value="delete">[delete condition]</option>
            </select>
        </div>
        <div class="col-auto">
            <label for="condition-operator-${index}" class="form-label">Condition</label>
            <select class="form-select" id="condition-operator-${index}" onchange="updateConditionOperator(${index})">
                <option value="is">is</option>
                <option value="is_ignore_case">is (ignore casing)</option>
                <option value="contains">includes</option>
                <option value="contains_ignore_case">includes (ignore casing)</option>
                <option value="matches_regex">matches (regex)</option>
                <option value="matches_regex_ignore_case">matches (regex, attribute lowercased)</option>
            </select>
        </div>
        <div class="col-5">
            <label for="condition-value-${index}" class="form-label">Value</label>
            <input class="form-control" type="text" placeholder="Value" id="condition-value-${index}" onchange="updateConditionValue(${index})">
        </div>
    </form>`;
    return rootElement;
};

const getActionInputBody = (index, actionType) => {
    const inputComponents = ACTION_INPUT_BODY_MAP[actionType];
    if (!inputComponents) {
        console.warn('unknown action type ' + actionType);
        return '';
    }
    let output = '';
    for (const component of inputComponents) {
        let componentId = component.id_prefix + '-' + index;
        output += `<label for="${componentId}" class="form-label">${component.label}</label>`;
        if (component.type === 'textarea') {
            output += `<textarea class="form-control" rows="3" id="${componentId}" onchange="updateActionInput(${index}, &quot;${component.argument}&quot;, &quot;${componentId}&quot;)"></textarea>`;
        } else if (component.type === 'text') {
            output += `<input class="form-control mb-3" type="text" id="${componentId}" onchange="updateActionInput(${index}, &quot;${component.argument}&quot;, &quot;${componentId}&quot;)">`;
        }
    }
    return output;
}

const setActionType = (index) => {
    const actionTypeValue = document.getElementById(`action-type-${index}`).value;
    if (actionTypeValue === 'delete') {
        // delete the action
        currentRule.actions.splice(index, 1);
        renderRule();
        return;
    }
    let action = {
        type: actionTypeValue,
        arguments: {}
    };
    if (!(actionTypeValue in ACTION_INPUT_BODY_MAP)) {
        console.warn(`failed to set action type due to invalid action type: ${actionTypeValue}`)
        renderRule();
        return;
    }
    for (const argument of ACTION_INPUT_BODY_MAP[actionTypeValue]) {
        action.arguments[argument.argument] = '';
    }
    currentRule.actions[index] = action;
    renderRule();
}

const updateActionInput = (index, argument, componentId) => {
    if (currentRule == null) {
        return;
    }
    currentRule.actions[index].arguments[argument] = document.getElementById(componentId).value;
}

const generateAction = (index, actionType) => {
    if (isNaN(index)) {
        return null;
    }
    let rootElement = document.createElement('div');
    rootElement.id = `action-${index}`;
    rootElement.classList.add('mb-3');
    rootElement.innerHTML = `<form class="row gy-2 gx-3 align-items-center">
        <div class="col-auto">
            <label for="action-type-${index}" class="form-label">Action</label>
            <select class="form-select" id="action-type-${index}" onchange="setActionType(${index})">
                <option value="set_request_url">Set request URL</option>
                <option value="set_request_body">Set request body</option>
                <option value="set_request_header">Set request header</option>
                <option value="set_request_method">Set request method</option>
                <option value="set_response_body">Set response body</option>
                <option value="set_response_header">Set response header</option>
                <option value="set_response_status">Set response status code</option>
                <option value="replace_request_url">Replace request URL</option>
                <option value="replace_request_body">Replace request body</option>
                <option value="replace_response_body">Replace response body</option>
                <option value="delete">[delete action]</option>
            </select>
        </div>
    </form>
    <div class="mb-3" id="action-input">
        ${getActionInputBody(index, actionType)}
    </div>`;
    return rootElement;
};

// determines if we need to set the token
const authenticate = () => {
    if (window.location.pathname !== '/authenticate') {
        return;
    }
    let queryParts = window.location.search.substring(1).split('=');
    if (queryParts.length < 2 || queryParts[0] !== 'token') {
        return;
    }
    setToken(queryParts[1]);
    window.history.pushState(null, null, '/rules');
}

const refreshRules = async () => {
    let resp = await makeGetRequest('/v1/rules');
    if (!resp) {
        return;
    }
    rules = resp.rules;
    for (const rule in rules) {
        if (currentRule && currentRule.name === rules[rule].name) {
            currentRuleIndex = rule;
        }
    }
    updateRuleList();
}

const pushCurrentRule = async () => {
    if (!currentRule) {
        console.error('cannot push currentRule since it is not truthy');
        return;
    }
    let resp = await makePostRequest('/v1/rules', {rule: currentRule});
    if (resp) {
        rules = resp.rules;
        for (const rule in rules) {
            if (currentRule.name === rules[rule].name) {
                currentRuleIndex = rule;
            }
        }
        return;
    }
    console.error('encountered strange error while posting rule');
}

const deleteRule = async (rule) => {
    let resp = await makePostRequest('/v1/rules/delete', {rule});
    if (resp) {
        rules = resp.rules;
        for (const rule in rules) {
            if (currentRule.name === rules[rule].name) {
                currentRuleIndex = rule;
            }
        }
    }
    if (rule.name === currentRule.name) {
        originalRule = null;
        currentRule = null;
        currentRuleIndex = -1;
        updateRuleList();
        renderRule();
    }
}

const deleteAllRules = async () => {
    let resp = await makePostRequest('/v1/rules/delete-all', {});
    if (resp) {
        rules = resp.rules;
        originalRule = null;
        currentRule = null;
        currentRuleIndex = -1;
        updateRuleList();
        renderRule();
    }
}

const saveRule = async () => {
    if (!currentRule || !originalRule) {
        return;
    }
    if (currentRule.name === '') {
        alert('please name your rule.');
        return;
    }
    let resp = await pushCurrentRule();
    if (originalRule.name !== currentRule.name) {
        // delete older rule
        await deleteRule(originalRule);
    }
    currentRule = rules[currentRuleIndex];
    updateRuleList();
    renderRule();
}

const renderRule = () => {
    
    if (unauthenticated) {
        document.getElementById('nullstate').hidden = true;
        document.getElementById('rule-list-container').hidden = true;
        document.getElementById('primary-state').hidden = true;
        document.getElementById('unauthenticated-state').hidden = false;
        return;
    }

    if (!currentRule) {
        // show nullstate and return.
        document.getElementById('nullstate').hidden = false;
        document.getElementById('rule-list-container').hidden = false;
        document.getElementById('primary-state').hidden = true;
        document.getElementById('unauthenticated-state').hidden = true;
        return;
    }

    document.getElementById('nullstate').hidden = true;
    document.getElementById('rule-list-container').hidden = false;
    document.getElementById('primary-state').hidden = false;
    document.getElementById('unauthenticated-state').hidden = true;

    document.getElementById('rule-name-label').innerText = currentRule.name;
    document.getElementById('rule-name').value = currentRule.name;
    document.getElementById('rule-enabled').checked = currentRule.enabled;
    document.getElementById('rule-type').value = currentRule.type;
    document.getElementById('conditions-all-required').checked = currentRule.all_conditions_required;
    document.getElementById('conditions').innerHTML = '';
    for (const index in currentRule.conditions) {
        const condition = currentRule.conditions[index];
        document.getElementById('conditions').appendChild(generateCondition(index));
        document.getElementById(`condition-type-${index}`).value = condition.type;
        document.getElementById(`condition-operator-${index}`).value = condition.operator;
        document.getElementById(`condition-value-${index}`).value = condition.value;
    }
    document.getElementById('actions').innerHTML = '';
    for (const index in currentRule.actions) {
        const action = currentRule.actions[index];
        document.getElementById('actions').appendChild(generateAction(index, action.type));
        document.getElementById(`action-type-${index}`).value = action.type;
        for (const argument of ACTION_INPUT_BODY_MAP[action.type]) {
            document.getElementById(argument.id_prefix + '-' + index).value = action.arguments[argument.argument];
        }
    }

}

const startClient = async () => {
    authenticate();
    await refreshRules();
    renderRule();
}

(() => {
    startClient();
})();