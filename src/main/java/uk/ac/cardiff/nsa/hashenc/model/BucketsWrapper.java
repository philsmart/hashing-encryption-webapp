package uk.ac.cardiff.nsa.hashenc.model;

import java.util.Collections;
import java.util.List;



public class BucketsWrapper {
    
    private int[] buckets;
    
    private List<String[]> exampleCollisions;

    public BucketsWrapper(int[] buckets, List<String[]> exampleCollisions) {
        super();
        this.buckets = buckets;
        this.exampleCollisions = Collections.unmodifiableList(exampleCollisions);
    }

    public int[] getBuckets() {
        return buckets;
    }

    public List<String[]> getExampleCollisions() {
        return exampleCollisions;
    }


    
    

}
