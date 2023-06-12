namespace Serwis.Models.Entities
{
    public class LeapYearCheck
    {
        public int LeapYearCheckId { get; set; }

        public int? UserId { get; set; }
        public virtual User? User { get; set; } = null;

        public string? Name { get; set; }
        public int Year { get; set; }
        public bool IsLeap { get; set; }
        public DateTime CheckedAt { get; set; }
    }
}
