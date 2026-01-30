# trappsec
Trappsec is an open-source framework that helps developers catch attackers probing their APIs. It provides simple deception primitives to confirm malicious intent while blending into your codebase. It places a high value on the ability to attribute attacks to specific identities. With alerts that include intent and attribution, security teams can respond more effectively to attacks.

![Trappsec Flow](/assets/images/trappsec-flow.webp)

## deception primitives
We are starting out with 2 primitives (decoy routes and honey fields) with the hope to add more in the future. Each primitive must be paired with a lure strategy (think bait, breadcrumbs, etc.) in order to be effective at attracting or diverting attackers from the real API.

### 1. Decoy Routes
Fake endpoints that are not part of your API but can be designed to blend within.

### 2. Honey Fields
Fake fields that appear contextually relevant to your API.

## Support
contact us at [nikhil@ftfy.co](mailto:nikhil@ftfy.co)