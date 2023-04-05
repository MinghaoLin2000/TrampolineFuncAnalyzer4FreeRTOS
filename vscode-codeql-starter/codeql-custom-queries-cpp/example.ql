/**
 * @kind path-problem
 */
import cpp
import DataFlow::PathGraph
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.dataflow.TaintTracking

class MPUTask extends Function {
    MPUTask() {
        this.getADeclarationLocation().getFile().getAbsolutePath().matches("%Source/include/mpu_prototypes.h")
    }
}

class MPUTaskTaintedParament extends Parameter {
    MPUTaskTaintedParament() {
        this.getFunction() instanceof MPUTask
        // and not this.getFunction().getParameter(0) = this // maybe ?
    }
}

// find arbitrary write
class MPUTaskArbWCfg extends TaintTracking::Configuration {
    MPUTaskArbWCfg () { this = "MPUTaskArbWCfg" }
    override predicate isSource(DataFlow::Node source) {
        source.asParameter() instanceof MPUTaskTaintedParament
    }
    override predicate isSink(DataFlow::Node sink) {
        exists(AssignArithmeticOperation ao,AssignBitwiseOperation ag,AssignExpr ae| 
            ae.getLValue().getAChild*() = sink.asExpr() or ag.getLValue().getAChild*() = sink.asExpr() or ao.getLValue().getAChild*() = sink.asExpr()
        )
    }
    //this ignore the number
    //override predicate isSanitizer(DataFlow::Node node) {
       // not node.getType().getUnderlyingType() instanceof PointerType
     // }
    override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
        exists(FieldAccess fa |
            fa = node2.asExpr()
            and node1.asExpr() = fa.getQualifier()
        )
    }
}


// find arbitrary read
class MPUTaskInfoLeak extends TaintTracking::Configuration {
    MPUTaskInfoLeak () { this = "MPUTaskInfoLeak" }
    override predicate isSource(DataFlow::Node source) {
        source.asParameter() instanceof MPUTaskTaintedParament
        
    }
    override predicate isSink(DataFlow::Node sink) {
        exists(MPUTask mpu_task, ReturnStmt ret |
            ret.getExpr() = sink.asExpr()
            and ret.getEnclosingFunction() = mpu_task
        )

    }
    override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
        exists(FieldAccess fa |
            fa = node2.asExpr()
            and node1.asExpr() = fa.getQualifier()
        )
    }
}
// implicit influence including integer overflow and DOS
class MPUTaskimplicit extends TaintTracking::Configuration {
    MPUTaskimplicit () { this = "MPUTaskimplicit" }
    override predicate isSource(DataFlow::Node source) {
        source.asParameter() instanceof MPUTaskTaintedParament
        
    }
    override predicate isSink(DataFlow::Node sink) {
        exists(Operation op|
            op.getAnOperand()=sink.asExpr()
            

        )

    }
    override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
        exists(FieldAccess fa |
            fa = node2.asExpr()
            and node1.asExpr() = fa.getQualifier()
        )
    }
}



// ================================================================

 from MPUTaskArbWCfg cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink) 
 //and source.getNode().getFunction().getName()="MPU_xQueueCreateSet"
 //select source, sink, sink.getNode().getLocation()

// ================================================================

//from MPUTaskInfoLeak cfg, DataFlow::PathNode source, DataFlow::PathNode sink
//where cfg.hasFlowPath(source, sink)
//select source, sink, sink.getNode().getLocation(),source.getNode().getFunction().getName()

//from MPUTaskimplicit cfg, DataFlow::PathNode source, DataFlow::PathNode sink
//where cfg.hasFlowPath(source, sink) 
//and source.getNode().getFunction().getName()="MPU_xTimerIsTimerActive"
// ================================================================
//select source, sink, sink.getNode().getLocation()
//select source, source.getNode().getFunction().getName(),sink,source.getNode().getLocation(),sink.getNode().getLocation()
select source.getNode().getFunction().getName()