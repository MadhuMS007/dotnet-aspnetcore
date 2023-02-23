// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.App.Analyzers.Infrastructure;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.AspNetCore.Http.Generators.StaticRouteHandlerModel;

namespace Microsoft.AspNetCore.Http.Generators;

[Generator]
public sealed class RequestDelegateGenerator : IIncrementalGenerator
{
    private static readonly string[] _knownMethods =
    {
        "MapGet",
        "MapPost",
        "MapPut",
        "MapDelete",
        "MapPatch",
    };

    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var endpointsWithDiagnostics = context.SyntaxProvider.CreateSyntaxProvider(
            predicate: (node, _) => node is InvocationExpressionSyntax
            {
                Expression: MemberAccessExpressionSyntax
                {
                    Name: IdentifierNameSyntax
                    {
                        Identifier: { ValueText: var method }
                    }
                },
                ArgumentList: { Arguments: { Count: 2 } args }
            } && _knownMethods.Contains(method),
            transform: (context, token) =>
            {
                var operation = context.SemanticModel.GetOperation(context.Node, token) as IInvocationOperation;
                var wellKnownTypes = WellKnownTypes.GetOrCreate(context.SemanticModel.Compilation);
                return new Endpoint(operation, wellKnownTypes);
            })
            .WithTrackingName(GeneratorSteps.EndpointModelStep);

        context.RegisterSourceOutput(endpointsWithDiagnostics, (context, endpoint) =>
        {
            var (filePath, _) = endpoint.Location;
            foreach (var diagnostic in endpoint.Diagnostics)
            {
                context.ReportDiagnostic(Diagnostic.Create(diagnostic, endpoint.Operation.Syntax.GetLocation(), filePath));
            }
        });

        var endpoints = endpointsWithDiagnostics
            .Where(endpoint => endpoint.Diagnostics.Count == 0)
            .WithTrackingName(GeneratorSteps.EndpointsWithoutDiagnosicsStep);

        var thunks = endpoints.Select((endpoint, _) => $$"""
            [{{endpoint.EmitSourceKey()}}] = (
               (methodInfo, options) =>
                {
                    Debug.Assert(options?.EndpointBuilder != null, "EndpointBuilder not found.");
                    options.EndpointBuilder.Metadata.Add(new SourceKey{{endpoint.EmitSourceKey()}});
                    return new RequestDelegateMetadataResult { EndpointMetadata = options.EndpointBuilder.Metadata.AsReadOnly() };
                },
                (del, options, inferredMetadataResult) =>
                {
                    var handler = ({{endpoint.EmitHandlerDelegateCast()}})del;
                    EndpointFilterDelegate? filteredInvocation = null;

                    if (options?.EndpointBuilder?.FilterFactories.Count > 0)
                    {
                        filteredInvocation = GeneratedRouteBuilderExtensionsCore.BuildFilterDelegate(ic =>
                        {
                            if (ic.HttpContext.Response.StatusCode == 400)
                            {
                                return ValueTask.FromResult<object?>(Results.Empty);
                            }
                            {{endpoint.EmitFilteredInvocation()}}
                        },
                        options.EndpointBuilder,
                        handler.Method);
                    }

                    {{endpoint.EmitRequestHandler(baseIndent: 5)}}
                    {{endpoint.EmitFilteredRequestHandler(baseIndent: 5)}}
                    RequestDelegate targetDelegate = filteredInvocation is null ? RequestHandler : RequestHandlerFiltered;
                    var metadata = inferredMetadataResult?.EndpointMetadata ?? ReadOnlyCollection<object>.Empty;
                    return new RequestDelegateResult(targetDelegate, metadata);
                }),
""");

        var stronglyTypedEndpointDefinitions = endpoints
            .Collect()
            .Select((endpoints, _) =>
            {
                var dedupedByDelegate = endpoints.Distinct(EndpointDelegateComparer.Instance);
                var code = new StringBuilder();
                using var stringWriter = new StringWriter(CultureInfo.InvariantCulture);
                using var codeWriter = new CodeWriter(stringWriter, baseIndent: 2);
                foreach (var endpoint in dedupedByDelegate)
                {
                    codeWriter.WriteLine($"internal static global::Microsoft.AspNetCore.Builder.RouteHandlerBuilder {endpoint.HttpMethod}(");
                    codeWriter.Indent++;
                    codeWriter.WriteLine("this global::Microsoft.AspNetCore.Routing.IEndpointRouteBuilder endpoints,");
                    codeWriter.WriteLine(@"[global::System.Diagnostics.CodeAnalysis.StringSyntax(""Route"")] string pattern,");
                    codeWriter.WriteLine($"global::{endpoint.EmitHandlerDelegateType()} handler,");
                    codeWriter.WriteLine(@"[global::System.Runtime.CompilerServices.CallerFilePath] string filePath = """",");
                    codeWriter.WriteLine("[global::System.Runtime.CompilerServices.CallerLineNumber]int lineNumber = 0)");
                    codeWriter.Indent--;
                    codeWriter.StartBlock();
                    codeWriter.WriteLine("return global::Microsoft.AspNetCore.Http.Generated.GeneratedRouteBuilderExtensionsCore.MapCore(");
                    codeWriter.Indent++;
                    codeWriter.WriteLine("endpoints,");
                    codeWriter.WriteLine("pattern,");
                    codeWriter.WriteLine("handler,");
                    codeWriter.WriteLine($"{endpoint.EmitVerb()},");
                    codeWriter.WriteLine("filePath,");
                    codeWriter.WriteLine("lineNumber);");
                    codeWriter.Indent--;
                    codeWriter.EndBlock();
                }

                return stringWriter.ToString();
            });

        var thunksAndEndpoints = thunks.Collect().Combine(stronglyTypedEndpointDefinitions);

        context.RegisterSourceOutput(thunksAndEndpoints, (context, sources) =>
        {
            var (thunks, endpointsCode) = sources;

            if (thunks.IsDefaultOrEmpty || string.IsNullOrEmpty(endpointsCode))
            {
                return;
            }

            var thunksCode = new StringBuilder();
            foreach (var thunk in thunks)
            {
                thunksCode.AppendLine(thunk);
            }

            var code = RequestDelegateGeneratorSources.GetGeneratedRouteBuilderExtensionsSource(
                genericThunks: string.Empty,
                thunks: thunksCode.ToString(),
                endpoints: endpointsCode);

            context.AddSource("GeneratedRouteBuilderExtensions.g.cs", code);
        });
    }
}
