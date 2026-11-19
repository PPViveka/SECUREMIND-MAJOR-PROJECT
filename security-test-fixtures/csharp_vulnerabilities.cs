using System.Data.SqlClient;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class VulnerableController : Controller
{
    private const string ApiKey = "demo-csharp-key-123456789";

    public IActionResult Search(string name)
    {
        using var connection = new SqlConnection("Server=localhost");
        using var command = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", connection);
        Process.Start("sh", "-c " + name);
        return Redirect(Request.Query["next"]);
    }
}
