import javascript
import DOM
import ClientSideJSONInjection
import ClientSideOpenRedirect
import ClientSideRequestForgery
import CookieManipulation
import DomainManipulation
import WebsocketHijacking
import RegexInjection
import CrossSiteScripting   
import PostMessageManipulation
import WebStorageManipulation
import HTMLInjection


class ClientSideSinks extends DataFlow::Node {
    ClientSideSinks() {
        this instanceof ClientSideJSONInjectionSink or 
        this instanceof ClientSideOpenRedirectSink or
        this instanceof ClientSideRequestForgerySink or
        this instanceof ClientSideCookieManipulationSink or
        this instanceof ClientSideDomainManipulationSink or
        this instanceof WebSocketHijackingSink or
        this instanceof RegexInjectionSink or
        this instanceof CrossSiteScriptingSink or
        this instanceof PostMessageManipulationSink or
        this instanceof WebStorageManipulationSink or
        this instanceof HTMLInjectionSink
    }
}  


