using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace XDR.Manager.utils.counter {
    public class CounterDoc
    {
        [BsonId]                     
        public string Id { get; set; } = null!;

        [BsonElement("seq")]
        public int Seq { get; set; }
    }

    public static class Counters
    {
        public static async Task<int> NextAsync(
            IMongoDatabase db,
            string counterName,
            CancellationToken ct = default)
        {
            var counters = db.GetCollection<CounterDoc>("counters");

            var filter = Builders<CounterDoc>.Filter.Eq(x => x.Id, counterName);
            var update = Builders<CounterDoc>.Update.Inc(x => x.Seq, 1);

            var opts = new FindOneAndUpdateOptions<CounterDoc>
            {
                IsUpsert = true,
                ReturnDocument = ReturnDocument.After
            };

            var doc = await counters.FindOneAndUpdateAsync(filter, update, opts, ct);
            return doc.Seq; 
        }
    }
}