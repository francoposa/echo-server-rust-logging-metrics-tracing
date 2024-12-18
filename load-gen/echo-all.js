import http from 'k6/http';
import {sleep} from 'k6';


// run for an hour in fluctuating 1-minute stages
let stages = [];
for (let i = 0; i < 60; i++) {
    stages.push({duration: '1m', target: Math.floor(Math.random() * 10)});
}

export const options = {
    stages: stages,
};

// TODO get these from environment
const echoDefaultEndpoint = 'http://echo-server:8080/api/v0/echo'
const echoJSONEndpoint = 'http://echo-server:8080/api/v0/echo/json'

const endpoints = [
    echoDefaultEndpoint,
    echoJSONEndpoint,
];

const supportedMethods = ['GET', 'POST', 'PUT']

const endpointContentTypes = new Map(
    [
        [echoDefaultEndpoint, 'application/octet-stream'],
        [echoJSONEndpoint, 'application/json'],
    ]
)

let getRandomArrayItem = (arr) => {
    return arr[Math.floor((Math.random() * arr.length))];
}

export default function () {
    const url = getRandomArrayItem(endpoints)
    const method = getRandomArrayItem(supportedMethods)
    const contentType = endpointContentTypes.get(url)

    const payload = JSON.stringify({
        'hello': 'world',
    });

    const params = {
        headers: {
            'Content-Type': contentType,
        },
    };

    http.request(method, url, payload, params);
    sleep(Math.random() * 10);
}
