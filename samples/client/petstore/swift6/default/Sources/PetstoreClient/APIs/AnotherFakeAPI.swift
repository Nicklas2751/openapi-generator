//
// AnotherFakeAPI.swift
//
// Generated by openapi-generator
// https://openapi-generator.tech
//

import Foundation

open class AnotherFakeAPI {

    /**
     To test special tags
     
     - parameter uuidTest: (header) to test uuid example value 
     - parameter body: (body) client model 
     - parameter openAPIClient: The OpenAPIClient that contains the configuration for the http request.
     - returns: Client
     */
    @available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    open class func call123testSpecialTags(uuidTest: UUID, body: Client, openAPIClient: OpenAPIClient = OpenAPIClient.shared) async throws(ErrorResponse) -> Client {
        return try await call123testSpecialTagsWithRequestBuilder(uuidTest: uuidTest, body: body, openAPIClient: openAPIClient).execute().body
    }

    /**
     To test special tags
     - PATCH /another-fake/dummy
     - To test special tags and operation ID starting with number
     - parameter uuidTest: (header) to test uuid example value 
     - parameter body: (body) client model 
     - parameter openAPIClient: The OpenAPIClient that contains the configuration for the http request.
     - returns: RequestBuilder<Client> 
     */
    open class func call123testSpecialTagsWithRequestBuilder(uuidTest: UUID, body: Client, openAPIClient: OpenAPIClient = OpenAPIClient.shared) -> RequestBuilder<Client> {
        let localVariablePath = "/another-fake/dummy"
        let localVariableURLString = openAPIClient.basePath + localVariablePath
        let localVariableParameters = JSONEncodingHelper.encodingParameters(forEncodableObject: body, codableHelper: openAPIClient.codableHelper)

        let localVariableUrlComponents = URLComponents(string: localVariableURLString)

        let localVariableNillableHeaders: [String: Any?] = [
            "Content-Type": "application/json",
            "uuid_test": uuidTest.encodeToJSON(codableHelper: openAPIClient.codableHelper),
        ]

        let localVariableHeaderParameters = APIHelper.rejectNilHeaders(localVariableNillableHeaders)

        let localVariableRequestBuilder: RequestBuilder<Client>.Type = openAPIClient.requestBuilderFactory.getBuilder()

        return localVariableRequestBuilder.init(method: "PATCH", URLString: (localVariableUrlComponents?.string ?? localVariableURLString), parameters: localVariableParameters, headers: localVariableHeaderParameters, requiresAuthentication: false, openAPIClient: openAPIClient)
    }
}
