// generated by codegen/codegen.py
private import codeql.swift.generated.Synth
private import codeql.swift.generated.Raw
import codeql.swift.elements.expr.Expr

module Generated {
  class ExplicitCastExpr extends Synth::TExplicitCastExpr, Expr {
    /**
     * Gets the sub expression of this explicit cast expression.
     *
     * This includes nodes from the "hidden" AST. It can be overridden in subclasses to change the
     * behavior of both the `Immediate` and non-`Immediate` versions.
     */
    Expr getImmediateSubExpr() {
      result =
        Synth::convertExprFromRaw(Synth::convertExplicitCastExprToRaw(this)
              .(Raw::ExplicitCastExpr)
              .getSubExpr())
    }

    /**
     * Gets the sub expression of this explicit cast expression.
     */
    final Expr getSubExpr() { result = getImmediateSubExpr().resolve() }
  }
}
