// API Controller
[ApiController]
[Route("api/[controller]")]
public class TransactionsController : ControllerBase
{
    private readonly IClxDataService _dataService;
    private readonly ILogger<TransactionsController> _logger;

    public TransactionsController(IClxDataService dataService, ILogger<TransactionsController> logger)
    {
        _dataService = dataService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<TransactionSummaryResponse>> GetTransactions(
        [FromQuery] DateTime fromDate,
        [FromQuery] DateTime toDate,
        CancellationToken ct)
    {
        try
        {
            // Validate date range
            var monthsDiff = GetMonthDifference(fromDate, toDate);
            if (monthsDiff > 12)
            {
                return BadRequest(new { Error = "Maximum range is 12 months" });
            }

            if (monthsDiff != 1 && monthsDiff != 3 && monthsDiff != 6 && monthsDiff != 12)
            {
                return BadRequest(new { Error = "Only 1, 3, 6, or 12 month ranges are supported" });
            }

            _logger.LogInformation("Fetching transactions from {From} to {To} ({Months} months)",
                fromDate, toDate, monthsDiff);

            var result = await _dataService.GetDataAsync(fromDate, toDate, ct);

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching transaction data");
            return StatusCode(500, new { Error = "Error fetching transaction data" });
        }
    }

    private int GetMonthDifference(DateTime start, DateTime end)
    {
        return ((end.Year - start.Year) * 12) + end.Month - start.Month + 1;
    }
}

// Data Models

// CLX API Response (what comes from the external API)
public class ClxApiResponse
{
    public decimal SettledTransactions { get; set; }
    public decimal AuthorizedTransactions { get; set; }
}

// Monthly Transaction Data
public class MonthlyTransactions
{
    public string MonthYear { get; set; } = string.Empty; // e.g., "2024-01"
    public decimal SettledTransactions { get; set; }
    public decimal AuthorizedTransactions { get; set; }
}

// Final Response to Client
public class TransactionSummaryResponse
{
    public decimal TotalSettledTransactions { get; set; }
    public decimal TotalAuthorizedTransactions { get; set; }
    public Dictionary<string, MonthlyTransactions> MonthlyBreakdown { get; set; } = new();
}

/* Example Response:
{
    "totalSettledTransactions": 150000.00,
    "totalAuthorizedTransactions": 175000.00,
    "monthlyBreakdown": {
        "Month1": {
            "monthYear": "2024-01",
            "settledTransactions": 50000.00,
            "authorizedTransactions": 55000.00
        },
        "Month2": {
            "monthYear": "2024-02",
            "settledTransactions": 45000.00,
            "authorizedTransactions": 52000.00
        },
        "Month3": {
            "monthYear": "2024-03",
            "settledTransactions": 55000.00,
            "authorizedTransactions": 68000.00
        }
    }
}
*/