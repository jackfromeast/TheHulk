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


    string getLabel() {
        if this instanceof ClientSideJSONInjectionSink
            then result = "ClientSideJSONInjectionSink"
        else if this instanceof ClientSideOpenRedirectSink
            then result = "ClientSideOpenRedirectSink"
        else if this instanceof ClientSideRequestForgerySink
            then result = "ClientSideRequestForgerySink"
        else if this instanceof ClientSideCookieManipulationSink
            then result = "ClientSideCookieManipulationSink"
        else if this instanceof ClientSideDomainManipulationSink
            then result = "ClientSideDomainManipulationSink"
        else if this instanceof WebSocketHijackingSink
            then result = "WebSocketHijackingSink"
        else if this instanceof RegexInjectionSink
            then result = "RegexInjectionSink"
        else if this instanceof CrossSiteScriptingSink
            then result = "CrossSiteScriptingSink"
        else if this instanceof PostMessageManipulationSink
            then result = "PostMessageManipulationSink"
        else if this instanceof WebStorageManipulationSink
            then result = "WebStorageManipulationSink"
        else if this instanceof HTMLInjectionSink
            then result = "HTMLInjectionSink"
        else
            result = "UnknownSink"
    }
}  


