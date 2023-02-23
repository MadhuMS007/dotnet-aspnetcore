// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text;

namespace Microsoft.AspNetCore.Http.Generators.StaticRouteHandlerModel.Emitters;
internal static class EndpointParameterEmitter
{
    internal static void EmitSpecialParameterPreparation(this EndpointParameter endpointParameter, CodeWriter codeWriter) =>
        codeWriter.WriteLine($"var {endpointParameter.Name}_local = {endpointParameter.AssigningCode};");

    internal static void EmitQueryParameterPreparation(this EndpointParameter endpointParameter, CodeWriter codeWriter)
    {
        // Preamble for diagnostics purposes.
        codeWriter.WriteLine(endpointParameter.EmitParameterDiagnosticComment());

        // Grab raw input from HttpContext.
        codeWriter.WriteLine($"var {endpointParameter.Name}_raw = {endpointParameter.AssigningCode};");

        // If we are not optional, then at this point we can just assign the string value to the handler argument,
        // otherwise we need to detect whether no value is provided and set the handler argument to null to
        // preserve consistency with RDF behavior. We don't want to emit the conditional block to avoid
        // compiler errors around null handling.
        if (endpointParameter.IsOptional)
        {
            codeWriter.WriteLine($"var {endpointParameter.HandlerArgument} = {endpointParameter.Name}_raw.Count > 0 ? {endpointParameter.Name}_raw.ToString() : null;");
        }
        else
        {
            codeWriter.WriteLine($"if (StringValues.IsNullOrEmpty({endpointParameter.Name}_raw))");
            codeWriter.StartBlock();
            codeWriter.WriteLine("wasParamCheckFailure = true;");
            codeWriter.EndBlock();
            codeWriter.WriteLine($"var {endpointParameter.HandlerArgument} = {endpointParameter.Name}_raw.ToString();");
        }
    }

    internal static void EmitJsonBodyParameterPreparationString(this EndpointParameter endpointParameter, CodeWriter codeWriter)
    {
        // Preamble for diagnostics purposes.
        codeWriter.WriteLine(endpointParameter.EmitParameterDiagnosticComment());

        // Invoke TryResolveBody method to parse JSON and set
        // status codes on exceptions.
        codeWriter.WriteLine($"var (isSuccessful, {endpointParameter.Name}_local) = {endpointParameter.AssigningCode};");

        // If binding from the JSON body fails, we exit early. Don't
        // set the status code here because assume it has been set by the
        // TryResolveBody method.
        codeWriter.WriteLine("if (!isSuccessful)");
        codeWriter.StartBlock();
        codeWriter.WriteLine("return;");
        codeWriter.EndBlock();
    }

    internal static void EmitServiceParameterPreparation(this EndpointParameter endpointParameter, CodeWriter codeWriter)
    {
        codeWriter.WriteLine(endpointParameter.EmitParameterDiagnosticComment());

        // Requiredness checks for services are handled by the distinction
        // between GetRequiredService and GetService in the AssigningCode.
        codeWriter.WriteLine($"var {endpointParameter.HandlerArgument} = {endpointParameter.AssigningCode};");
    }

    private static string EmitParameterDiagnosticComment(this EndpointParameter endpointParameter) =>
        $"// Endpoint Parameter: {endpointParameter.Name} (Type = {endpointParameter.Type}, IsOptional = {endpointParameter.IsOptional}, Source = {endpointParameter.Source})";
}
