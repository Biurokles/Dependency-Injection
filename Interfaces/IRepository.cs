using System.Linq.Expressions;

namespace Serwis.Interfaces
{
    public interface IRepository<TEntity> where TEntity : class
    {
        IQueryable<TEntity> Get(Expression<Func<TEntity, bool>> predicate, params Expression<Func<TEntity, object>>[] includes);
        IQueryable<TEntity> GetAll(params Expression<Func<TEntity, object>>[] includes);
        void Add(TEntity entity);
        void Remove(TEntity entity);
        void Update(TEntity entity);
        void SaveChanges();
    }
}
