// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/so/ent/predicate"
	"github.com/lightsparkdev/spark/so/ent/signingnonce"
)

// SigningNonceQuery is the builder for querying SigningNonce entities.
type SigningNonceQuery struct {
	config
	ctx        *QueryContext
	order      []signingnonce.OrderOption
	inters     []Interceptor
	predicates []predicate.SigningNonce
	modifiers  []func(*sql.Selector)
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the SigningNonceQuery builder.
func (snq *SigningNonceQuery) Where(ps ...predicate.SigningNonce) *SigningNonceQuery {
	snq.predicates = append(snq.predicates, ps...)
	return snq
}

// Limit the number of records to be returned by this query.
func (snq *SigningNonceQuery) Limit(limit int) *SigningNonceQuery {
	snq.ctx.Limit = &limit
	return snq
}

// Offset to start from.
func (snq *SigningNonceQuery) Offset(offset int) *SigningNonceQuery {
	snq.ctx.Offset = &offset
	return snq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (snq *SigningNonceQuery) Unique(unique bool) *SigningNonceQuery {
	snq.ctx.Unique = &unique
	return snq
}

// Order specifies how the records should be ordered.
func (snq *SigningNonceQuery) Order(o ...signingnonce.OrderOption) *SigningNonceQuery {
	snq.order = append(snq.order, o...)
	return snq
}

// First returns the first SigningNonce entity from the query.
// Returns a *NotFoundError when no SigningNonce was found.
func (snq *SigningNonceQuery) First(ctx context.Context) (*SigningNonce, error) {
	nodes, err := snq.Limit(1).All(setContextOp(ctx, snq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{signingnonce.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (snq *SigningNonceQuery) FirstX(ctx context.Context) *SigningNonce {
	node, err := snq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first SigningNonce ID from the query.
// Returns a *NotFoundError when no SigningNonce ID was found.
func (snq *SigningNonceQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = snq.Limit(1).IDs(setContextOp(ctx, snq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{signingnonce.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (snq *SigningNonceQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := snq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single SigningNonce entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one SigningNonce entity is found.
// Returns a *NotFoundError when no SigningNonce entities are found.
func (snq *SigningNonceQuery) Only(ctx context.Context) (*SigningNonce, error) {
	nodes, err := snq.Limit(2).All(setContextOp(ctx, snq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{signingnonce.Label}
	default:
		return nil, &NotSingularError{signingnonce.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (snq *SigningNonceQuery) OnlyX(ctx context.Context) *SigningNonce {
	node, err := snq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only SigningNonce ID in the query.
// Returns a *NotSingularError when more than one SigningNonce ID is found.
// Returns a *NotFoundError when no entities are found.
func (snq *SigningNonceQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = snq.Limit(2).IDs(setContextOp(ctx, snq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{signingnonce.Label}
	default:
		err = &NotSingularError{signingnonce.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (snq *SigningNonceQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := snq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of SigningNonces.
func (snq *SigningNonceQuery) All(ctx context.Context) ([]*SigningNonce, error) {
	ctx = setContextOp(ctx, snq.ctx, ent.OpQueryAll)
	if err := snq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*SigningNonce, *SigningNonceQuery]()
	return withInterceptors[[]*SigningNonce](ctx, snq, qr, snq.inters)
}

// AllX is like All, but panics if an error occurs.
func (snq *SigningNonceQuery) AllX(ctx context.Context) []*SigningNonce {
	nodes, err := snq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of SigningNonce IDs.
func (snq *SigningNonceQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if snq.ctx.Unique == nil && snq.path != nil {
		snq.Unique(true)
	}
	ctx = setContextOp(ctx, snq.ctx, ent.OpQueryIDs)
	if err = snq.Select(signingnonce.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (snq *SigningNonceQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := snq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (snq *SigningNonceQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, snq.ctx, ent.OpQueryCount)
	if err := snq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, snq, querierCount[*SigningNonceQuery](), snq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (snq *SigningNonceQuery) CountX(ctx context.Context) int {
	count, err := snq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (snq *SigningNonceQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, snq.ctx, ent.OpQueryExist)
	switch _, err := snq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (snq *SigningNonceQuery) ExistX(ctx context.Context) bool {
	exist, err := snq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the SigningNonceQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (snq *SigningNonceQuery) Clone() *SigningNonceQuery {
	if snq == nil {
		return nil
	}
	return &SigningNonceQuery{
		config:     snq.config,
		ctx:        snq.ctx.Clone(),
		order:      append([]signingnonce.OrderOption{}, snq.order...),
		inters:     append([]Interceptor{}, snq.inters...),
		predicates: append([]predicate.SigningNonce{}, snq.predicates...),
		// clone intermediate query.
		sql:  snq.sql.Clone(),
		path: snq.path,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		CreateTime time.Time `json:"create_time,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.SigningNonce.Query().
//		GroupBy(signingnonce.FieldCreateTime).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (snq *SigningNonceQuery) GroupBy(field string, fields ...string) *SigningNonceGroupBy {
	snq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &SigningNonceGroupBy{build: snq}
	grbuild.flds = &snq.ctx.Fields
	grbuild.label = signingnonce.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		CreateTime time.Time `json:"create_time,omitempty"`
//	}
//
//	client.SigningNonce.Query().
//		Select(signingnonce.FieldCreateTime).
//		Scan(ctx, &v)
func (snq *SigningNonceQuery) Select(fields ...string) *SigningNonceSelect {
	snq.ctx.Fields = append(snq.ctx.Fields, fields...)
	sbuild := &SigningNonceSelect{SigningNonceQuery: snq}
	sbuild.label = signingnonce.Label
	sbuild.flds, sbuild.scan = &snq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a SigningNonceSelect configured with the given aggregations.
func (snq *SigningNonceQuery) Aggregate(fns ...AggregateFunc) *SigningNonceSelect {
	return snq.Select().Aggregate(fns...)
}

func (snq *SigningNonceQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range snq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, snq); err != nil {
				return err
			}
		}
	}
	for _, f := range snq.ctx.Fields {
		if !signingnonce.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if snq.path != nil {
		prev, err := snq.path(ctx)
		if err != nil {
			return err
		}
		snq.sql = prev
	}
	return nil
}

func (snq *SigningNonceQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*SigningNonce, error) {
	var (
		nodes = []*SigningNonce{}
		_spec = snq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*SigningNonce).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &SigningNonce{config: snq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	if len(snq.modifiers) > 0 {
		_spec.Modifiers = snq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, snq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (snq *SigningNonceQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := snq.querySpec()
	if len(snq.modifiers) > 0 {
		_spec.Modifiers = snq.modifiers
	}
	_spec.Node.Columns = snq.ctx.Fields
	if len(snq.ctx.Fields) > 0 {
		_spec.Unique = snq.ctx.Unique != nil && *snq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, snq.driver, _spec)
}

func (snq *SigningNonceQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(signingnonce.Table, signingnonce.Columns, sqlgraph.NewFieldSpec(signingnonce.FieldID, field.TypeUUID))
	_spec.From = snq.sql
	if unique := snq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if snq.path != nil {
		_spec.Unique = true
	}
	if fields := snq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, signingnonce.FieldID)
		for i := range fields {
			if fields[i] != signingnonce.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := snq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := snq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := snq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := snq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (snq *SigningNonceQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(snq.driver.Dialect())
	t1 := builder.Table(signingnonce.Table)
	columns := snq.ctx.Fields
	if len(columns) == 0 {
		columns = signingnonce.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if snq.sql != nil {
		selector = snq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if snq.ctx.Unique != nil && *snq.ctx.Unique {
		selector.Distinct()
	}
	for _, m := range snq.modifiers {
		m(selector)
	}
	for _, p := range snq.predicates {
		p(selector)
	}
	for _, p := range snq.order {
		p(selector)
	}
	if offset := snq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := snq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ForUpdate locks the selected rows against concurrent updates, and prevent them from being
// updated, deleted or "selected ... for update" by other sessions, until the transaction is
// either committed or rolled-back.
func (snq *SigningNonceQuery) ForUpdate(opts ...sql.LockOption) *SigningNonceQuery {
	if snq.driver.Dialect() == dialect.Postgres {
		snq.Unique(false)
	}
	snq.modifiers = append(snq.modifiers, func(s *sql.Selector) {
		s.ForUpdate(opts...)
	})
	return snq
}

// ForShare behaves similarly to ForUpdate, except that it acquires a shared mode lock
// on any rows that are read. Other sessions can read the rows, but cannot modify them
// until your transaction commits.
func (snq *SigningNonceQuery) ForShare(opts ...sql.LockOption) *SigningNonceQuery {
	if snq.driver.Dialect() == dialect.Postgres {
		snq.Unique(false)
	}
	snq.modifiers = append(snq.modifiers, func(s *sql.Selector) {
		s.ForShare(opts...)
	})
	return snq
}

// SigningNonceGroupBy is the group-by builder for SigningNonce entities.
type SigningNonceGroupBy struct {
	selector
	build *SigningNonceQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (sngb *SigningNonceGroupBy) Aggregate(fns ...AggregateFunc) *SigningNonceGroupBy {
	sngb.fns = append(sngb.fns, fns...)
	return sngb
}

// Scan applies the selector query and scans the result into the given value.
func (sngb *SigningNonceGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, sngb.build.ctx, ent.OpQueryGroupBy)
	if err := sngb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*SigningNonceQuery, *SigningNonceGroupBy](ctx, sngb.build, sngb, sngb.build.inters, v)
}

func (sngb *SigningNonceGroupBy) sqlScan(ctx context.Context, root *SigningNonceQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(sngb.fns))
	for _, fn := range sngb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*sngb.flds)+len(sngb.fns))
		for _, f := range *sngb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*sngb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := sngb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// SigningNonceSelect is the builder for selecting fields of SigningNonce entities.
type SigningNonceSelect struct {
	*SigningNonceQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (sns *SigningNonceSelect) Aggregate(fns ...AggregateFunc) *SigningNonceSelect {
	sns.fns = append(sns.fns, fns...)
	return sns
}

// Scan applies the selector query and scans the result into the given value.
func (sns *SigningNonceSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, sns.ctx, ent.OpQuerySelect)
	if err := sns.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*SigningNonceQuery, *SigningNonceSelect](ctx, sns.SigningNonceQuery, sns, sns.inters, v)
}

func (sns *SigningNonceSelect) sqlScan(ctx context.Context, root *SigningNonceQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(sns.fns))
	for _, fn := range sns.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*sns.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := sns.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
