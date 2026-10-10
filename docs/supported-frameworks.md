---
layout: default
title: Supported Frameworks
permalink: /supported-frameworks/
tagline: "All frameworks supported across Python, Node.js, and Go."
---

<table>
  <thead>
    <tr>
      <th>Language</th>
      <th>Framework</th>
      <th>Minimum version</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="7"><b>Python</b><br>3.10+</td>
      <td>Flask</td>
      <td>2.0</td>
    </tr>
    <tr>
      <td>FastAPI</td>
      <td>0.95</td>
    </tr>
    <tr>
      <td>Starlette</td>
      <td>0.24</td>
    </tr>
    <tr>
      <td>Litestar</td>
      <td>2.13</td>
    </tr>
    <tr>
      <td>Django</td>
      <td>3.2</td>
    </tr>
    <tr>
      <td>Sanic</td>
      <td>24.6</td>
    </tr>
    <tr>
      <td>Tornado</td>
      <td>6.0</td>
    </tr>
    <tr>
      <td rowspan="5"><b>Node.js</b><br>20+</td>
      <td>Express</td>
      <td>4.17 (and 5.x)</td>
    </tr>
    <tr>
      <td>NestJS</td>
      <td>10</td>
    </tr>
    <tr>
      <td>Fastify</td>
      <td>4</td>
    </tr>
    <tr>
      <td>Hapi</td>
      <td>20</td>
    </tr>
    <tr>
      <td>Koa</td>
      <td>2.13 with @koa/router 10</td>
    </tr>
    <tr>
      <td rowspan="3"><b>Go</b><br>1.26+</td>
      <td>net/http</td>
      <td>standard library</td>
    </tr>
    <tr>
      <td>Gin</td>
      <td>1.12</td>
    </tr>
    <tr>
      <td>Echo</td>
      <td>4.16</td>
    </tr>
  </tbody>
</table>

Minimum versions are the oldest releases the integration tests pass on. CI checks them on every change: each Python framework on Python 3.10, every Node framework on Node 20. Go adapters require these versions in their `go.mod`, so Go's minimum version selection enforces them. Older releases may work but are not tested; Litestar before 2.13 and Sanic before 24.6 are known to miss honey fields.

> Missing your favorite framework? [Raise a request here](https://github.com/trappsec-dev/trappsec/discussions/new?category=feature-requests).
