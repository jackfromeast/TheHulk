// JALANGI DO NOT INSTRUMENT
/**
 * Description:
 * --------------------------------
 * This script records the coverage information for the analysis.
 * 
 * Usage: 
 * --------------------------------
 */

import iidToLocation from "./utils/iidToLocation.js";
const LAST_IID = "LAST_IID";

/**
 * Bits for coverage info propagation
 */

const IS_TOUCHED = 0x1;
const CONDITIONAL_TRUE = 0x2;
const CONDITIONAL_FALSE = 0x4;

export class Coverage {

	/**
   * Creates an instance of Coverage.
   * @param {any} sandbox The Jalangi sandbox
   * _branches is an array of coverages for a given sid where the sid is branches[sid+1]
   * @memberOf Coverage
   */
	constructor(sandbox) {
		this._sandbox = sandbox;
		this._branches = [];
		this._branchFilenameMap = [];
		this._lastIid = 0; //Store the last IID touched for search strategizer

		this.brachTrace = {};
	}

	end() {
		const payload = {
			code: {}
		};

		for (let i = 0; i < this._branches.length; i++) {
            
			//SID are indexed from 1 not 0
			const localSid = i + 1;

			if (this._branches[i] !== undefined) {

				//Deep copy the smap
				const map = JSON.parse(JSON.stringify(this._sandbox.smap[localSid]));

				//Strip away any non SID related entities
				for (const localIid in map) {
					if (isNaN(parseInt(localIid))) {
						delete map[localIid];
					} else {
						map[localIid] = iidToLocation(this._sandbox, localSid, localIid);
					}
				}

				payload["code"][this._branchFilenameMap[i]] = {
					smap: map,
					branches: this._branches[i]
				};
			}
		}

		payload["path"] = this.brachTrace;
		payload[LAST_IID] =	 this._lastIid;
		return payload;
	}

	getBranchInfo() {

		//-1 from 1-indexed sid to start from 0
		const localIndex = this._sandbox.sid - 1;
		let branchInfo = this._branches[localIndex];

		if (!branchInfo) {
			branchInfo = {};
			this._branches[localIndex] = branchInfo;
			const map = this._sandbox.smap[this._sandbox.sid];
			this._branchFilenameMap[localIndex] = map ? map.originalCodeFileName : "Broken Filename";
		}

		return branchInfo;
	}

	touch(iid) {
		this.getBranchInfo()[iid] |= IS_TOUCHED;
		this._lastIid = iid;
	}

	touch_cnd(iid, result) {
		this.touch(iid);
		this.getBranchInfo()[iid] |= (result ? CONDITIONAL_TRUE : CONDITIONAL_FALSE);

		this.touchBranch(iid, result);
	}

	last() {
		return this._lastIid || 0;
	}

	touchBranch(iid, result) {
		let binResult = result ? 1 : 0;
		let gid = this._sandbox.sid + ":" + iid;

		if(Object.keys(this.brachTrace).includes(gid)){
			this.brachTrace[gid].push(binResult);
		}else{
			this.brachTrace[gid] = [binResult];
		}
	}
}